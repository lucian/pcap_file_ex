# HTTP/2 Stream Reconstruction Specification

**Date**: 2025-12-15
**Status**: Draft
**Scope**: Analysis only (no playback server), cleartext prior-knowledge h2c only

## Overview

This specification defines HTTP/2 support for PcapFileEx - the ability to parse HTTP/2 frames from PCAP files and reconstruct HTTP/2 streams (request/response pairs).

## Dependencies

- `{:hpax, "~> 1.0"}` - HPACK header compression (from elixir-mint)

## Scope Limitations

- **Cleartext only**: No TLS-encrypted HTTP/2 (h2)
- **Prior-knowledge h2c only**: No HTTP/1.1 Upgrade flow support (may be added later)
- **No server push**: PUSH_PROMISE frames are ignored
- **Analysis only**: No playback server implementation

---

## Design Decisions

### TCP Reassembly with Direction Tracking

HTTP/2 frames can span multiple TCP segments. The implementation **must**:

1. Use existing `PcapFileEx.TCP` module for TCP stream reassembly
2. **Preserve direction metadata** with each reassembled segment
3. Maintain per-direction frame buffers (client→server and server→client)
4. Only attempt frame parsing on complete frame data (header + payload)

```
TCP Flow: client:54321 <-> server:443

Segment from client: [Frame Header (9 bytes)][Payload bytes 0-500]
Segment from client: [Payload bytes 501-1000]
Segment from server: [Response Frame...]
Segment from client: [Payload bytes 1001-1500][Next Frame Header...]
```

**Critical**: After TCP reassembly, we must know which endpoint sent each segment. The `DirectionalSegment` struct carries this:

```elixir
%DirectionalSegment{
  data: binary(),
  direction: :client_to_server | :server_to_client,
  timestamp: DateTime.t()
}
```

Each connection maintains **two frame buffers**:
- `client_to_server_buffer` - for decoding with `server_decode_table`
- `server_to_client_buffer` - for decoding with `client_decode_table`

### Client/Server Identification

**Primary method**: Connection preface detection.

The HTTP/2 connection preface (`"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"`) is sent only by the client. The `FrameBuffer` module detects this and identifies the sender as client.

**Preface detection is owned entirely by FrameBuffer** - not duplicated in the analyzer. The FrameBuffer:
1. Buffers incoming bytes
2. Detects preface (may be split across segments)
3. Returns `{:preface_detected, sender_is_client: true}` when found
4. Strips the preface and continues with frame parsing

**Fallback** (mid-connection capture): Use stream ID semantics:
- Odd stream IDs (1, 3, 5...): Client-initiated
- First HEADERS with `:method` identifies sender as client

### Exchange Keying

Use **stream ID** as the unique key for request/response pairing, not signature hashes. HTTP/2 guarantees exactly one transaction per stream ID within a connection.

```elixir
# Key: {tcp_flow_key, http2_stream_id}
exchanges = %{
  {{client_endpoint, server_endpoint}, 1} => %Exchange{...},
  {{client_endpoint, server_endpoint}, 3} => %Exchange{...},
}
```

This avoids collision issues with parallel identical requests.

### Return Type for Incomplete Streams

```elixir
@spec analyze(source) :: {:ok, [Exchange.t()], [IncompleteExchange.t()]} | {:error, term()}
```

Returns separate lists for:
- **Complete exchanges**: Both request and response have END_STREAM
- **Incomplete exchanges**: Terminated by RST_STREAM, GOAWAY, or truncated capture

### Incomplete Stream Detection Rules

A stream is marked incomplete with specific reasons:

| Condition | Reason |
|-----------|--------|
| RST_STREAM frame received | `{:rst_stream, error_code}` |
| GOAWAY received and stream_id > last_stream_id | `{:goaway, last_stream_id}` |
| PCAP ends with request but no response headers | `:truncated_no_response` |
| PCAP ends with response headers but no END_STREAM | `:truncated_incomplete_response` |
| PCAP ends mid-header-block (awaiting CONTINUATION) | `:truncated_incomplete_headers` |
| TCP FIN received before END_STREAM | `:tcp_fin_without_end_stream` |
| HPACK decode error | `{:hpack_error, reason}` |

Detection at PCAP end:
```
FUNCTION finalize_streams(conn):
    FOR each stream IN conn.streams:
        IF stream.awaiting_continuation:
            stream.termination_reason = :truncated_incomplete_headers
        ELSE IF stream.request_headers != nil AND stream.response_headers == nil:
            stream.termination_reason = :truncated_no_response
        ELSE IF NOT stream.request_complete OR NOT stream.response_complete:
            stream.termination_reason = :truncated_incomplete_response
```

---

## Algorithm: HTTP/2 Stream Reconstruction

### Phase 1: PCAP Analysis - Extract Request/Response Pairs

```
FUNCTION analyze_pcap(pcap_file):

    // Data structures
    connections = {}      // Key: tcp_flow_key (normalized), Value: ConnectionState

    // ─────────────────────────────────────────────────────────────
    // STEP 0: TCP Reassembly WITH DIRECTION
    // ─────────────────────────────────────────────────────────────

    // Returns segments with direction metadata preserved
    directional_segments = reassemble_tcp_with_direction(pcap_file)
    // Each segment: {flow_key, direction: :a_to_b | :b_to_a, data, timestamp}

    FOR each segment IN directional_segments:

        flow_key = normalize_flow_key(segment.flow_key)  // Always (min_endpoint, max_endpoint)
        conn = connections[flow_key] OR new ConnectionState(flow_key)

        // ─────────────────────────────────────────────────────────
        // STEP 1: Route to correct directional buffer
        // ─────────────────────────────────────────────────────────

        // Before client/server identified, use arbitrary labels A/B
        // After identification, map to client_to_server / server_to_client
        buffer = select_buffer(conn, segment.direction)
        buffer = FrameBuffer.append(buffer, segment.data, segment.timestamp)

        // ─────────────────────────────────────────────────────────
        // STEP 2: Check for preface (FrameBuffer handles this)
        // ─────────────────────────────────────────────────────────

        IF NOT conn.client_identified:
            {preface_result, buffer} = FrameBuffer.check_preface(buffer)
            IF preface_result == :preface_found:
                // Sender of this segment is the client
                conn.client = endpoint_for_direction(conn.flow_key, segment.direction, :sender)
                conn.server = endpoint_for_direction(conn.flow_key, segment.direction, :receiver)
                conn.client_identified = true
                conn.identified_via = :preface
                conn.direction_history[segment.direction] = :client
                // FrameBuffer already stripped preface internally

        // ─────────────────────────────────────────────────────────
        // STEP 3: Parse frames from buffer
        // ─────────────────────────────────────────────────────────

        WHILE FrameBuffer.has_complete_frame?(buffer):
            result = FrameBuffer.next_frame(buffer)

            IF result is {:error, reason, new_buffer}:
                // Malformed frame - log and skip
                buffer = new_buffer
                CONTINUE

            {:ok, frame, frame_timestamp, buffer} = result
            // frame_timestamp is when first byte of frame was received

            // ─────────────────────────────────────────────────────
            // STEP 4: Determine frame direction (is_from_client)
            // ─────────────────────────────────────────────────────

            is_from_client = determine_frame_direction(conn, frame, segment.direction)

            // ─────────────────────────────────────────────────────
            // STEP 5: Process control frames (stream 0)
            // ─────────────────────────────────────────────────────

            IF frame.stream_id == 0:
                // is_from_client may be nil for mid-connection captures
                // before we've identified client/server
                process_control_frame(conn, frame, is_from_client, segment.direction)
                CONTINUE

            // ─────────────────────────────────────────────────────
            // STEP 6: Get or create stream state
            // ─────────────────────────────────────────────────────

            stream = conn.streams[frame.stream_id] OR new StreamState(
                stream_id: frame.stream_id,
                created_at: frame_timestamp  // First frame seen for this stream
            )

            // ─────────────────────────────────────────────────────
            // STEP 7: Process frame by type
            // ─────────────────────────────────────────────────────

            process_stream_frame(conn, stream, frame, is_from_client, frame_timestamp)

            conn.streams[frame.stream_id] = stream

        // Store updated buffer back into connection
        conn = store_buffer(conn, segment.direction, buffer)
        connections[flow_key] = conn

    // ─────────────────────────────────────────────────────────────
    // STEP 8: Finalize and build exchange lists
    // ─────────────────────────────────────────────────────────────

    complete_exchanges = []
    incomplete_exchanges = []

    FOR each (flow_key, conn) IN connections:
        // Mark truncated streams
        finalize_streams(conn)

        FOR each (stream_id, stream) IN conn.streams:
            exchange = build_exchange(stream, flow_key, conn)

            IF stream.request_complete AND stream.response_complete:
                complete_exchanges.append(exchange)
            ELSE:
                incomplete_exchanges.append(
                    IncompleteExchange(exchange, reason: stream.termination_reason)
                )

    RETURN {:ok, complete_exchanges, incomplete_exchanges}
```

### Direction Inference (Mid-Connection Capture Support)

```
FUNCTION determine_frame_direction(conn, frame, segment_direction):
    // ─────────────────────────────────────────────────────────────
    // Case 1: Client already identified via preface
    // ─────────────────────────────────────────────────────────────

    IF conn.client_identified:
        // Map segment direction to client/server based on known endpoints
        IF segment_direction == direction_for_endpoint(conn, conn.client):
            RETURN true   // is_from_client
        ELSE:
            RETURN false  // is_from_server

    // ─────────────────────────────────────────────────────────────
    // Case 2: Mid-connection capture - infer from stream semantics
    // ─────────────────────────────────────────────────────────────

    // For stream 0 (control frames), we can't infer direction reliably
    // without more context. Use direction_history if available.
    IF frame.stream_id == 0:
        // Check if we've already learned this direction from a prior frame
        IF conn.direction_history[segment_direction] == :client:
            RETURN true
        ELSE IF conn.direction_history[segment_direction] == :server:
            RETURN false
        ELSE:
            // Unknown - will be resolved when we see first HEADERS frame
            // For now, return nil to indicate unknown (caller should handle)
            RETURN nil

    // For non-zero streams, use stream ID semantics + stream state
    stream = conn.streams[frame.stream_id]

    // Odd stream IDs are client-initiated (RFC 7540 §5.1.1)
    // This means the CLIENT sent the first HEADERS on this stream
    is_client_initiated_stream = (frame.stream_id % 2 == 1)

    IF frame.type == HEADERS:
        // First HEADERS on client-initiated stream = request = from client
        // Subsequent HEADERS = response = from server
        IF is_client_initiated_stream:
            IF stream == nil OR stream.request_headers == nil:
                // This is the request - sender is client
                infer_client_direction(conn, segment_direction)
                RETURN true
            ELSE:
                // This is the response - sender is server
                RETURN false
        ELSE:
            // Even stream ID = server push (we ignore) or invalid
            // Treat as server-originated
            RETURN false

    ELSE IF frame.type == DATA:
        // DATA direction depends on whether we're in request or response phase
        IF stream == nil:
            // DATA before HEADERS is protocol error, but assume client
            RETURN is_client_initiated_stream

        IF is_client_initiated_stream:
            // Request body comes from client, response body from server
            IF stream.response_headers == nil:
                // Still in request phase
                RETURN true
            ELSE:
                // In response phase - but client could still be sending body
                // Check if request is complete
                IF stream.request_complete:
                    RETURN false  // Response body from server
                ELSE:
                    // Ambiguous - use segment direction tracking
                    RETURN infer_from_segment_history(conn, segment_direction)

    ELSE:
        // RST_STREAM, PRIORITY, etc. - use stream initiator as hint
        RETURN is_client_initiated_stream


FUNCTION infer_client_direction(conn, segment_direction):
    // We've determined this segment direction corresponds to the client
    // Update connection state to map directions to endpoints
    conn.direction_history[segment_direction] = :client
    conn.direction_history[opposite_direction(segment_direction)] = :server

    IF NOT conn.client_identified:
        conn.client = endpoint_for_direction(conn.flow_key, segment_direction, :sender)
        conn.server = endpoint_for_direction(conn.flow_key, segment_direction, :receiver)
        conn.client_identified = true
        conn.identified_via = :stream_semantics

        // Replay any deferred SETTINGS frames now that we know directions
        replay_deferred_settings(conn)


FUNCTION infer_from_segment_history(conn, segment_direction):
    // When direction is ambiguous, check if we've seen this direction before
    // and what role it played
    IF conn.direction_history[segment_direction] == :client:
        RETURN true
    ELSE IF conn.direction_history[segment_direction] == :server:
        RETURN false
    ELSE:
        // No history - default based on stream semantics
        RETURN false


FUNCTION direction_for_endpoint(conn, endpoint):
    // Map an endpoint to its segment direction (as sender)
    // flow_key is normalized as (min_endpoint, max_endpoint)
    // :a_to_b means endpoint_a is the sender
    {endpoint_a, endpoint_b} = conn.flow_key

    IF endpoint == endpoint_a:
        RETURN :a_to_b  // endpoint_a sending to endpoint_b
    ELSE:
        RETURN :b_to_a  // endpoint_b sending to endpoint_a


FUNCTION endpoint_for_direction(flow_key, segment_direction, role):
    // Map a segment direction to an endpoint
    // flow_key: {endpoint_a, endpoint_b} tuple (normalized as min, max)
    // segment_direction: :a_to_b or :b_to_a
    // role: :sender or :receiver
    //
    // :a_to_b means: endpoint_a -> endpoint_b (a is sender, b is receiver)
    // :b_to_a means: endpoint_b -> endpoint_a (b is sender, a is receiver)

    {endpoint_a, endpoint_b} = flow_key

    IF segment_direction == :a_to_b:
        IF role == :sender:
            RETURN endpoint_a
        ELSE:
            RETURN endpoint_b
    ELSE:  // :b_to_a
        IF role == :sender:
            RETURN endpoint_b
        ELSE:
            RETURN endpoint_a


FUNCTION opposite_direction(direction):
    IF direction == :a_to_b:
        RETURN :b_to_a
    ELSE:
        RETURN :a_to_b


FUNCTION replay_deferred_settings(conn):
    // Now that we know client/server, process any SETTINGS frames
    // that were received before identification
    FOR each {segment_direction, frame} IN conn.deferred_settings:
        is_from_client = (conn.direction_history[segment_direction] == :client)
        process_settings(conn, frame, is_from_client)

    conn.deferred_settings = []  // Clear after replay
```

**Mid-Connection Capture Limitations:**

When capturing mid-connection (no preface seen):
1. HPACK dynamic table entries from before capture are lost → some headers may fail to decode
2. Static table entries (including `:method`, `:status`) decode correctly
3. Direction inference relies on stream ID parity and HEADERS ordering
4. Control frames (stream 0) before first HEADERS may be attributed incorrectly

### Control Frame Processing (Stream 0)

```
FUNCTION process_control_frame(conn, frame, is_from_client, segment_direction):
    // is_from_client may be nil for mid-connection captures before identification
    // segment_direction is always available for deferred processing

    SWITCH frame.type:

        CASE SETTINGS:
            IF frame.flags.ACK:
                // ACK is just confirmation - no action needed for analysis
                // (The sender already applied our settings when they received them)
                RETURN

            // RFC 7540/HPACK: Receiver applies SETTINGS immediately
            // The sender is telling us their decoder's table size limit
            IF is_from_client == nil:
                // Mid-connection: defer SETTINGS processing until we know direction
                // Store for later replay, or skip (documented limitation)
                conn.deferred_settings.append({segment_direction, frame})
                RETURN

            process_settings(conn, frame, is_from_client)

        CASE GOAWAY:
            conn.goaway_received = true
            conn.last_good_stream_id = parse_goaway_last_stream_id(frame)
            // Mark all streams > last_good_stream_id as incomplete
            FOR each stream IN conn.streams WHERE stream.stream_id > conn.last_good_stream_id:
                stream.terminated = true
                stream.termination_reason = {:goaway, conn.last_good_stream_id}

        CASE PING, WINDOW_UPDATE:
            // Ignore for analysis
```

### SETTINGS Frame Processing (RFC 7540 Compliant)

```
FUNCTION process_settings(conn, frame, is_from_client):

    // Parse settings payload (6 bytes per setting: 2-byte id + 4-byte value)
    FOR each (id, value) IN parse_settings(frame.payload):
        SWITCH id:

            CASE HEADER_TABLE_SIZE (0x1):
                // The sender is advertising their DECODER table size
                // We (as passive observer) use this to know the table size
                // for headers WE decode that THEY sent
                //
                // If client sends SETTINGS with HEADER_TABLE_SIZE=X:
                //   - Client's decoder table is X bytes
                //   - Server must encode headers to fit in X bytes
                //   - We decode server→client headers, so resize client_decode_table
                //
                // If server sends SETTINGS with HEADER_TABLE_SIZE=X:
                //   - Server's decoder table is X bytes
                //   - Client must encode headers to fit in X bytes
                //   - We decode client→server headers, so resize server_decode_table

                IF is_from_client:
                    // Client advertises its decoder size
                    // We need this for decoding server's headers TO the client
                    HPAX.resize(conn.client_decode_table, value)
                ELSE:
                    // Server advertises its decoder size
                    // We need this for decoding client's headers TO the server
                    HPAX.resize(conn.server_decode_table, value)

            CASE MAX_HEADER_LIST_SIZE (0x6):
                // Store for optional validation
                IF is_from_client:
                    conn.client_max_header_list_size = value
                ELSE:
                    conn.server_max_header_list_size = value

            // ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE,
            // MAX_FRAME_SIZE - not critical for passive analysis
```

### Stream Frame Processing

```
FUNCTION process_stream_frame(conn, stream, frame, is_from_client, frame_timestamp):

    SWITCH frame.type:

        CASE HEADERS:
            result = extract_header_block(frame)
            IF result is error:
                stream.error = result
                RETURN

            header_block = result.data
            end_stream = frame.flags.END_STREAM

            // Buffer for CONTINUATION if END_HEADERS not set
            IF NOT frame.flags.END_HEADERS:
                stream.pending_header_block = header_block
                stream.pending_end_stream = end_stream
                stream.pending_direction = is_from_client
                stream.awaiting_continuation = true
                RETURN

            // Decode complete header block
            decode_and_apply_headers(conn, stream, header_block, is_from_client, end_stream, frame_timestamp)

        CASE CONTINUATION:
            IF NOT stream.awaiting_continuation:
                stream.error = {:unexpected_continuation, frame.stream_id}
                RETURN

            // Append to pending header block
            stream.pending_header_block += frame.payload

            IF frame.flags.END_HEADERS:
                // Now decode the complete accumulated header block
                decode_and_apply_headers(
                    conn, stream,
                    stream.pending_header_block,
                    stream.pending_direction,
                    stream.pending_end_stream,
                    frame_timestamp  // Use END_HEADERS frame time
                )

                // Clear continuation state
                stream.awaiting_continuation = false
                stream.pending_header_block = <<>>
                stream.pending_end_stream = false
                stream.pending_direction = nil

        CASE DATA:
            result = extract_data_payload(frame)
            IF result is error:
                stream.error = result
                RETURN

            data = result.data

            IF is_from_client:
                stream.request_body.append(data)
                IF frame.flags.END_STREAM:
                    stream.request_complete = true
                    update_completed_at(stream, frame_timestamp)
            ELSE:
                stream.response_body.append(data)
                IF frame.flags.END_STREAM:
                    stream.response_complete = true
                    update_completed_at(stream, frame_timestamp)

        CASE RST_STREAM:
            stream.terminated = true
            stream.termination_reason = {:rst_stream, parse_error_code(frame.payload)}

        CASE PRIORITY:
            // Ignore for analysis

        CASE PUSH_PROMISE:
            // Ignore server push
```

### Header Decoding and Classification

```
FUNCTION decode_and_apply_headers(conn, stream, header_block, is_from_client, end_stream, frame_timestamp):

    // Select correct HPACK table based on sender
    IF is_from_client:
        // Client sent these headers → use server_decode_table
        // (server decodes what client sends)
        decode_table = conn.server_decode_table
    ELSE:
        // Server sent these headers → use client_decode_table
        decode_table = conn.client_decode_table

    // Decode via HPAX
    result = HPAX.decode(header_block, decode_table)

    IF result is error:
        stream.error = {:hpack_decode_error, result}
        stream.terminated = true
        stream.termination_reason = {:hpack_error, result}
        RETURN

    // Update decode table with new state
    IF is_from_client:
        conn.server_decode_table = result.new_table
    ELSE:
        conn.client_decode_table = result.new_table

    headers = Headers.from_list(result.headers)

    // Classify headers by pseudo-header presence
    IF headers.has(":method"):
        // Request headers (initial)
        stream.request_headers = headers
        IF end_stream:
            stream.request_complete = true
            update_completed_at(stream, frame_timestamp)

    ELSE IF headers.has(":status"):
        status = parse_int(headers.pseudo[":status"])

        IF status >= 100 AND status < 200:
            // Informational response (1xx) - store but don't mark complete
            stream.informational_responses.append(headers)
        ELSE:
            // Final response headers
            stream.response_headers = headers
            IF end_stream:
                stream.response_complete = true
                update_completed_at(stream, frame_timestamp)

    ELSE:
        // Trailing headers (no pseudo-headers)
        IF is_from_client:
            stream.request_trailers = headers
            stream.request_complete = true
            update_completed_at(stream, frame_timestamp)
        ELSE:
            stream.response_trailers = headers
            stream.response_complete = true
            update_completed_at(stream, frame_timestamp)
```

### Frame Payload Extraction (with bounds checking)

```
FUNCTION extract_header_block(frame):
    payload = frame.payload
    offset = 0
    pad_length = 0

    // Handle PADDED flag
    IF frame.flags.PADDED:
        IF byte_size(payload) < 1:
            RETURN {:error, :invalid_padding_no_length}

        pad_length = payload[0]
        offset = 1

        // Validate: pad_length must not exceed remaining payload
        IF pad_length > byte_size(payload) - offset:
            RETURN {:error, :invalid_padding_exceeds_payload}

    // Handle PRIORITY flag
    IF frame.flags.PRIORITY:
        // Need 5 bytes: E(1 bit) + Stream Dependency(31 bits) + Weight(8 bits)
        IF byte_size(payload) - offset - pad_length < 5:
            RETURN {:error, :invalid_priority_truncated}

        offset = offset + 5

    // Extract header block (everything between offset and padding)
    header_block_length = byte_size(payload) - offset - pad_length

    IF header_block_length < 0:
        RETURN {:error, :invalid_frame_structure}

    header_block = binary_part(payload, offset, header_block_length)

    RETURN {:ok, data: header_block}


FUNCTION extract_data_payload(frame):
    payload = frame.payload
    offset = 0
    pad_length = 0

    // Handle PADDED flag
    IF frame.flags.PADDED:
        IF byte_size(payload) < 1:
            RETURN {:error, :invalid_padding_no_length}

        pad_length = payload[0]
        offset = 1

        // Validate: pad_length must not exceed remaining payload
        IF pad_length > byte_size(payload) - offset:
            RETURN {:error, :invalid_padding_exceeds_payload}

    // Extract data (everything between offset and padding)
    data_length = byte_size(payload) - offset - pad_length

    IF data_length < 0:
        RETURN {:error, :invalid_frame_structure}

    data = binary_part(payload, offset, data_length)

    RETURN {:ok, data: data}
```

### Helper Functions

```
FUNCTION select_buffer(conn, direction):
    // Get the appropriate frame buffer for the segment direction
    IF direction == :a_to_b:
        RETURN conn.a_to_b_buffer
    ELSE:
        RETURN conn.b_to_a_buffer


FUNCTION store_buffer(conn, direction, buffer):
    // Store updated buffer back into connection
    IF direction == :a_to_b:
        conn.a_to_b_buffer = buffer
    ELSE:
        conn.b_to_a_buffer = buffer
    RETURN conn


// FrameBuffer.append implementation sketch (timestamp tracking)
FUNCTION FrameBuffer.append(buffer, data, timestamp):
    // Record timestamp for the start offset of this chunk
    start_offset = byte_size(buffer.buffer)
    buffer.timestamp_index.append({start_offset, timestamp})
    buffer.buffer = buffer.buffer <> data
    RETURN buffer


// FrameBuffer.next_frame looks up timestamp for first byte of frame
FUNCTION FrameBuffer.next_frame(buffer):
    // Parse frame header to get length
    <<length::24, _type::8, _flags::8, _reserved::1, _stream_id::31, _rest::binary>> = buffer.buffer
    frame_size = 9 + length  // header + payload

    // Get timestamp for first byte of frame (offset 0 in current buffer)
    frame_timestamp = timestamp_at(buffer, 0)

    // Extract frame bytes
    <<frame_bytes::binary-size(frame_size), remaining::binary>> = buffer.buffer

    // Parse frame from frame_bytes...
    frame = parse_frame(frame_bytes)

    // Shift timestamp_index to account for removed bytes
    updated_index = shift_timestamp_index(buffer.timestamp_index, frame_size)

    updated_buffer = %{buffer |
        buffer: remaining,
        timestamp_index: updated_index
    }

    RETURN {:ok, frame, frame_timestamp, updated_buffer}


// Shift timestamp_index after consuming bytes from buffer start
FUNCTION shift_timestamp_index(index, bytes_consumed):
    // Subtract bytes_consumed from all offsets
    // Remove entries that now have negative offsets (their data was consumed)
    // Keep at least the last entry with offset <= 0 for timestamp continuity

    shifted = []
    last_valid_timestamp = nil

    FOR each {offset, timestamp} IN index:
        new_offset = offset - bytes_consumed

        IF new_offset < 0:
            // This chunk's start is now before buffer start
            // Keep track of it in case it's the timestamp for offset 0
            last_valid_timestamp = timestamp
        ELSE:
            shifted.append({new_offset, timestamp})

    // If offset 0 has no entry but we have a prior timestamp, add it
    IF shifted is empty OR shifted[0].offset > 0:
        IF last_valid_timestamp != nil:
            shifted.prepend({0, last_valid_timestamp})

    RETURN shifted


// FrameBuffer.check_preface strips preface and shifts timestamp index
//
// INVARIANT: check_preface is only called when we want to check offset 0.
// The preface is always exactly 24 bytes ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").
// We only strip when:
//   1. Buffer has at least 24 bytes (otherwise :need_more_data)
//   2. Buffer starts with the full 24-byte preface at offset 0
//
// When stripping, we remove exactly 24 bytes from both:
//   - buffer.buffer (binary slice)
//   - timestamp_index (shift all offsets by 24)
// This keeps the timestamp index aligned with the buffer contents.
//
FUNCTION FrameBuffer.check_preface(buffer):
    IF buffer.preface_checked:
        // Already checked - return cached result
        IF buffer.preface_found:
            RETURN {:preface_found, buffer}
        ELSE:
            RETURN {:no_preface, buffer}

    IF byte_size(buffer.buffer) < 24:
        // Not enough data to determine - preface may arrive across segments
        RETURN {:need_more_data, buffer}

    // Check if first 24 bytes match the connection preface exactly
    <<first_24::binary-size(24), _rest::binary>> = buffer.buffer

    IF first_24 == @connection_preface:
        // Strip exactly 24 bytes from buffer and shift index by exactly 24
        <<_preface::binary-size(24), remaining::binary>> = buffer.buffer
        updated_index = shift_timestamp_index(buffer.timestamp_index, 24)

        updated_buffer = %{buffer |
            buffer: remaining,
            timestamp_index: updated_index,
            preface_checked: true,
            preface_found: true
        }
        RETURN {:preface_found, updated_buffer}
    ELSE:
        // Not HTTP/2 or mid-connection capture (preface already passed)
        updated_buffer = %{buffer |
            preface_checked: true,
            preface_found: false
        }
        RETURN {:no_preface, updated_buffer}


// timestamp_at finds the timestamp for a given byte offset
FUNCTION timestamp_at(buffer, offset):
    // Find the latest entry where start_offset <= offset
    // (the chunk that contains this byte)
    result = nil

    FOR each {start_offset, timestamp} IN buffer.timestamp_index:
        IF start_offset <= offset:
            result = timestamp
        ELSE:
            BREAK  // index is sorted, no need to continue

    RETURN result


FUNCTION update_completed_at(stream, timestamp):
    // Set completed_at when BOTH request and response are complete
    // This ensures completed_at reflects the final END_STREAM frame
    IF stream.request_complete AND stream.response_complete:
        IF stream.completed_at == nil:
            stream.completed_at = timestamp
```

### Exchange Timestamp Population Rules

When building `Exchange` or `IncompleteExchange` from `StreamState`:

| Field | Source | Description |
|-------|--------|-------------|
| `Exchange.start_timestamp` | `stream.created_at` | Timestamp of first frame seen for this stream |
| `Exchange.end_timestamp` | `stream.completed_at` | Timestamp when both request and response completed (final END_STREAM) |
| `IncompleteExchange.timestamp` | `stream.completed_at OR stream.created_at` | Use completed_at if available, else created_at |

**Rules:**

1. **created_at**: Set once when `StreamState` is first created (first frame seen for that stream_id)
2. **completed_at**: Set when **both** `request_complete` AND `response_complete` are true
   - Only set once (idempotent - first completion wins)
   - For complete exchanges, this is always the final END_STREAM frame time
3. **Incomplete exchanges**: Use `completed_at` if partial completion occurred, otherwise use `created_at`
4. **Terminated streams**: RST_STREAM/GOAWAY don't set `completed_at` (stream didn't complete normally)

```
FUNCTION build_exchange(stream, flow_key, conn):
    IF stream.request_complete AND stream.response_complete:
        RETURN Exchange(
            stream_id: stream.stream_id,
            tcp_flow: flow_key,
            request: build_request(stream),
            response: build_response(stream),
            start_timestamp: stream.created_at,
            end_timestamp: stream.completed_at
        )
    ELSE:
        RETURN IncompleteExchange(
            stream_id: stream.stream_id,
            tcp_flow: flow_key,
            request: try_build_request(stream),   // May be nil
            response: try_build_response(stream), // May be nil
            reason: stream.termination_reason,
            timestamp: stream.completed_at OR stream.created_at
        )
```

---

## Data Structures

### Frame

```elixir
defmodule PcapFileEx.HTTP2.Frame do
  @type frame_type ::
          :data | :headers | :priority | :rst_stream | :settings
          | :push_promise | :ping | :goaway | :window_update | :continuation

  @type flags :: %{
          end_stream: boolean(),
          end_headers: boolean(),
          padded: boolean(),
          priority: boolean(),
          ack: boolean()
        }

  @type t :: %__MODULE__{
          length: non_neg_integer(),
          type: frame_type(),
          type_byte: non_neg_integer(),
          flags: flags(),
          flags_byte: non_neg_integer(),
          stream_id: non_neg_integer(),
          payload: binary(),
          raw: binary()
        }

  defstruct [:length, :type, :type_byte, :flags, :flags_byte, :stream_id, :payload, :raw]

  @doc "Parse frame from buffer, returns {:ok, frame, rest} | {:need_more, bytes_needed} | {:error, reason}"
  @spec parse(binary()) :: {:ok, t(), binary()} | {:need_more, non_neg_integer()} | {:error, atom()}

  @doc "Extract header block from HEADERS/CONTINUATION frame, handling padding and priority"
  @spec extract_header_block(t()) :: binary()

  @doc "Extract data from DATA frame, handling padding"
  @spec extract_data(t()) :: binary()
end
```

### FrameBuffer (New)

```elixir
defmodule PcapFileEx.HTTP2.FrameBuffer do
  @moduledoc """
  Accumulates TCP payload bytes and extracts complete HTTP/2 frames.
  Handles cross-packet frame reassembly and connection preface detection.

  IMPORTANT: This module owns ALL preface detection logic. The analyzer
  should not duplicate preface checks - just call check_preface/1.

  ## Timestamp Tracking

  Each appended chunk carries a timestamp. When a frame is extracted,
  the timestamp returned is the time when the FIRST byte of that frame
  was received (not when the frame became complete). This provides
  accurate timing even for frames spanning multiple TCP segments.

  ## Buffer Mutation Invariants

  The buffer can ONLY be mutated through these three operations:

  1. `append/3` - Adds bytes to end, records timestamp at new offset
  2. `check_preface/1` - May strip 24 bytes from start (shifts timestamp_index)
  3. `next_frame/1` - Removes frame bytes from start (shifts timestamp_index)

  All operations that remove bytes from the buffer start MUST call
  `shift_timestamp_index/2` to maintain alignment between `buffer` and
  `timestamp_index`. Direct manipulation of the buffer binary or
  timestamp_index outside these functions is NOT allowed.

  Error paths that encounter malformed data should either:
  - Return the buffer unchanged (let caller decide how to proceed)
  - Skip a known number of bytes using the same shift mechanism

  There is no "drop arbitrary bytes" operation - the buffer is consumed
  strictly from the front via check_preface and next_frame.
  """

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  @preface_length 24

  @type preface_result :: :preface_found | :no_preface | :need_more_data

  @type chunk :: {binary(), DateTime.t()}  # {data, timestamp}

  @type t :: %__MODULE__{
          buffer: binary(),
          # Tracks timestamp for each byte offset: [{start_offset, timestamp}]
          # Sorted by start_offset ascending
          timestamp_index: [{non_neg_integer(), DateTime.t()}],
          preface_checked: boolean(),
          preface_found: boolean()
        }

  defstruct buffer: <<>>, timestamp_index: [], preface_checked: false, preface_found: false

  @spec new() :: t()

  @doc "Append data to buffer with timestamp"
  @spec append(t(), binary(), DateTime.t()) :: t()

  @doc """
  Check for connection preface at start of buffer.

  Returns:
  - :preface_found - Preface detected and stripped from buffer
  - :no_preface - Buffer doesn't start with preface (not HTTP/2 or mid-connection)
  - :need_more_data - Buffer has < 24 bytes, can't determine yet

  This function is idempotent - once preface is checked, subsequent calls
  return the cached result.
  """
  @spec check_preface(t()) :: {preface_result(), t()}

  @doc "Check if buffer contains a complete frame (9-byte header + payload)"
  @spec has_complete_frame?(t()) :: boolean()

  @doc """
  Parse and return next complete frame from buffer.

  Returns:
  - {:ok, frame, timestamp, updated_buffer} - Successfully parsed frame with timestamp
  - {:need_more, buffer} - Incomplete frame, need more data
  - {:error, reason, buffer} - Malformed frame

  The timestamp is the time when the FIRST byte of the frame was received,
  looked up from the timestamp_index.
  """
  @spec next_frame(t()) :: {:ok, Frame.t(), DateTime.t(), t()} | {:need_more, t()} | {:error, term(), t()}

  @doc "Get timestamp for byte offset (first timestamp <= offset)"
  @spec timestamp_at(t(), non_neg_integer()) :: DateTime.t() | nil
end
```

### Headers

```elixir
defmodule PcapFileEx.HTTP2.Headers do
  @type t :: %__MODULE__{
          pseudo: %{optional(String.t()) => String.t()},
          regular: %{optional(String.t()) => String.t() | [String.t()]}
        }

  defstruct pseudo: %{}, regular: %{}

  @spec from_list([{binary(), binary()}]) :: t()
  @spec method(t()) :: String.t() | nil
  @spec path(t()) :: String.t() | nil
  @spec status(t()) :: integer() | nil
  @spec authority(t()) :: String.t() | nil
  @spec is_request?(t()) :: boolean()
  @spec is_response?(t()) :: boolean()
  @spec is_trailers?(t()) :: boolean()  # No pseudo-headers present
end
```

### StreamState (Enhanced)

```elixir
defmodule PcapFileEx.HTTP2.StreamState do
  @type termination_reason ::
          # Protocol-level termination
          {:rst_stream, non_neg_integer()}
          | {:goaway, non_neg_integer()}
          # PCAP truncation
          | :truncated_no_response
          | :truncated_incomplete_response
          | :truncated_incomplete_headers
          # TCP-level issues
          | :tcp_fin_without_end_stream
          # Decode errors
          | {:hpack_error, term()}
          | {:frame_error, term()}

  @type t :: %__MODULE__{
          stream_id: non_neg_integer(),

          # Request
          request_headers: Headers.t() | nil,
          request_trailers: Headers.t() | nil,
          request_body: iodata(),
          request_complete: boolean(),

          # Response
          response_headers: Headers.t() | nil,
          response_trailers: Headers.t() | nil,
          response_body: iodata(),
          response_complete: boolean(),
          informational_responses: [Headers.t()],  # 1xx responses

          # State
          terminated: boolean(),
          termination_reason: termination_reason() | nil,
          error: term() | nil,

          # CONTINUATION handling
          awaiting_continuation: boolean(),
          pending_header_block: binary(),
          pending_end_stream: boolean(),        # END_STREAM from initial HEADERS
          pending_direction: boolean() | nil,   # is_from_client for pending block

          # Timestamps
          created_at: DateTime.t(),
          completed_at: DateTime.t() | nil
        }

  defstruct [
    :stream_id,
    request_headers: nil,
    request_trailers: nil,
    request_body: [],
    request_complete: false,
    response_headers: nil,
    response_trailers: nil,
    response_body: [],
    response_complete: false,
    informational_responses: [],
    terminated: false,
    termination_reason: nil,
    error: nil,
    awaiting_continuation: false,
    pending_header_block: <<>>,
    pending_end_stream: false,
    pending_direction: nil,
    created_at: nil,
    completed_at: nil
  ]
end
```

### Connection (Enhanced)

```elixir
defmodule PcapFileEx.HTTP2.Connection do
  @moduledoc """
  State for an HTTP/2 connection.

  Maintains dual frame buffers (one per direction) and dual HPACK tables.
  Direction is tracked from TCP reassembly, not inferred per-frame.
  """

  @type direction :: :a_to_b | :b_to_a

  @type t :: %__MODULE__{
          # Flow identification
          flow_key: {Endpoint.t(), Endpoint.t()},  # Normalized (min, max)

          # Endpoints (identified after preface or stream semantics)
          client: Endpoint.t() | nil,
          server: Endpoint.t() | nil,
          client_identified: boolean(),
          identified_via: :preface | :stream_semantics | nil,  # How client was identified

          # Direction tracking for mid-connection captures
          direction_history: %{direction() => :client | :server},  # Learned mappings
          deferred_settings: [{direction(), Frame.t()}],  # SETTINGS before identification

          # Streams
          streams: %{non_neg_integer() => StreamState.t()},

          # HPACK decode tables (separate per direction)
          # server_decode_table: decodes client→server headers (requests)
          # client_decode_table: decodes server→client headers (responses)
          server_decode_table: HPAX.table(),
          client_decode_table: HPAX.table(),

          # Dual frame buffers (one per direction)
          # Before client identification: a_to_b_buffer and b_to_a_buffer
          # After identification: maps to client_to_server / server_to_client
          a_to_b_buffer: FrameBuffer.t(),
          b_to_a_buffer: FrameBuffer.t(),

          # Settings (optional, for validation)
          client_max_header_list_size: non_neg_integer() | nil,
          server_max_header_list_size: non_neg_integer() | nil,

          # Connection state
          goaway_received: boolean(),
          last_good_stream_id: non_neg_integer() | nil
        }

  defstruct [
    flow_key: nil,
    client: nil,
    server: nil,
    client_identified: false,
    identified_via: nil,
    direction_history: %{},
    deferred_settings: [],
    streams: %{},
    server_decode_table: nil,
    client_decode_table: nil,
    a_to_b_buffer: nil,
    b_to_a_buffer: nil,
    client_max_header_list_size: nil,
    server_max_header_list_size: nil,
    goaway_received: false,
    last_good_stream_id: nil
  ]

  @default_header_table_size 4096

  @spec new({Endpoint.t(), Endpoint.t()}) :: t()
  def new(flow_key) do
    %__MODULE__{
      flow_key: flow_key,
      server_decode_table: HPAX.new(@default_header_table_size),
      client_decode_table: HPAX.new(@default_header_table_size),
      a_to_b_buffer: FrameBuffer.new(),
      b_to_a_buffer: FrameBuffer.new()
    }
  end

  @doc "Select frame buffer based on segment direction"
  @spec select_buffer(t(), direction()) :: FrameBuffer.t()

  @doc "Check if direction maps to client after identification"
  @spec is_from_client?(t(), direction()) :: boolean() | :unknown

  @doc "Decode headers using correct table based on sender"
  @spec decode_headers(t(), boolean(), binary()) ::
          {:ok, [{binary(), binary()}], t()} | {:error, term()}
end
```

### Exchange (Output)

```elixir
defmodule PcapFileEx.HTTP2.Exchange do
  @type request :: %{
          headers: Headers.t(),
          trailers: Headers.t() | nil,
          body: binary(),
          method: String.t(),
          path: String.t(),
          authority: String.t() | nil
        }

  @type response :: %{
          headers: Headers.t(),
          trailers: Headers.t() | nil,
          body: binary(),
          status: integer(),
          informational: [Headers.t()]  # 1xx responses
        }

  @type t :: %__MODULE__{
          stream_id: non_neg_integer(),
          tcp_flow: {Endpoint.t(), Endpoint.t()},
          request: request(),
          response: response(),
          start_timestamp: DateTime.t(),
          end_timestamp: DateTime.t()
        }

  defstruct [:stream_id, :tcp_flow, :request, :response, :start_timestamp, :end_timestamp]
end
```

### IncompleteExchange (New)

```elixir
defmodule PcapFileEx.HTTP2.IncompleteExchange do
  @moduledoc """
  Represents a partial HTTP/2 exchange that couldn't complete.
  The reason field indicates why the exchange is incomplete.
  """

  @type reason ::
          # Protocol-level termination
          {:rst_stream, error_code :: non_neg_integer()}
          | {:goaway, last_stream_id :: non_neg_integer()}
          # PCAP truncation (capture ended mid-stream)
          | :truncated_no_response           # Request sent, no response headers seen
          | :truncated_incomplete_response   # Response headers seen, no END_STREAM
          | :truncated_incomplete_headers    # Mid-CONTINUATION, waiting for END_HEADERS
          # TCP-level issues
          | :tcp_fin_without_end_stream      # TCP closed before HTTP/2 END_STREAM
          # Decode errors
          | {:hpack_error, term()}           # HPACK decompression failed
          | {:frame_error, term()}           # Malformed frame (bad padding, etc.)

  @type t :: %__MODULE__{
          stream_id: non_neg_integer(),
          tcp_flow: {Endpoint.t(), Endpoint.t()},
          request: Exchange.request() | nil,
          response: Exchange.response() | nil,
          reason: reason(),
          timestamp: DateTime.t()
        }

  defstruct [:stream_id, :tcp_flow, :request, :response, :reason, :timestamp]
end
```

---

## Public API

```elixir
defmodule PcapFileEx.HTTP2 do
  @moduledoc """
  HTTP/2 cleartext (h2c) stream reconstruction.

  Parses HTTP/2 frames from TCP payloads and reconstructs complete
  request/response exchanges. Supports prior-knowledge h2c only
  (no HTTP/1.1 Upgrade flow).

  ## Limitations

  - Cleartext only (no TLS/h2)
  - Prior-knowledge h2c only (no Upgrade)
  - Server push (PUSH_PROMISE) is ignored
  """

  alias PcapFileEx.HTTP2.{Exchange, IncompleteExchange}

  @doc """
  Analyzes a PCAP file and returns HTTP/2 exchanges.

  Returns `{:ok, complete, incomplete}` where:
  - `complete` - List of fully completed request/response exchanges
  - `incomplete` - List of partial exchanges (RST, GOAWAY, truncated)

  ## Example

      {:ok, complete, incomplete} = PcapFileEx.HTTP2.analyze("capture.pcap")

      IO.puts("Complete: \#{length(complete)}, Incomplete: \#{length(incomplete)}")

      Enum.each(complete, fn ex ->
        IO.puts("\#{ex.request.method} \#{ex.request.path} -> \#{ex.response.status}")
      end)

      Enum.each(incomplete, fn ex ->
        IO.puts("Incomplete stream \#{ex.stream_id}: \#{inspect(ex.reason)}")
      end)
  """
  @spec analyze(Path.t() | Enumerable.t()) ::
          {:ok, [Exchange.t()], [IncompleteExchange.t()]} | {:error, term()}
  def analyze(source)

  @doc """
  Returns a lazy stream of HTTP/2 exchanges (complete only).

  For incomplete exchanges, use `analyze/1` instead.

  ## Example

      PcapFileEx.HTTP2.stream_exchanges("capture.pcap")
      |> Stream.filter(fn ex -> ex.request.method == "POST" end)
      |> Enum.to_list()
  """
  @spec stream_exchanges(Path.t() | Enumerable.t(), keyword()) :: Enumerable.t()
  def stream_exchanges(source, opts \\ [])

  @doc """
  Detects if a TCP payload contains HTTP/2 data.

  Checks for connection preface or valid frame structure.
  Uses conservative detection to avoid false positives.
  """
  @spec http2?(binary()) :: boolean()
  def http2?(payload)
end
```

---

## Module Architecture

```
PcapFileEx.HTTP2 (public API)
  ├── HTTP2.Frame           # Parse 9-byte header + payload, handle padding
  ├── HTTP2.FrameBuffer     # Cross-packet frame reassembly
  ├── HTTP2.Headers         # Pseudo/regular header separation, trailers
  ├── HTTP2.StreamState     # Per-stream state with CONTINUATION support
  ├── HTTP2.Connection      # Multi-stream + dual HPACK tables + SETTINGS
  ├── HTTP2.Analyzer        # Main reconstruction algorithm
  ├── HTTP2.Exchange        # Complete request/response pair
  └── HTTP2.IncompleteExchange  # Partial exchange with reason
```

---

## Frame Parsing Details

### Frame Header (9 bytes)

```
+-----------------------------------------------+
|                 Length (24)                   |
+---------------+---------------+---------------+
|   Type (8)    |   Flags (8)   |
+-+-------------+---------------+---------------+
|R|                 Stream ID (31)              |
+=+=============================================================+
|                   Payload (0...)              |
+---------------------------------------------------------------+
```

### Frame Types and Flags

| Type | Code | Relevant Flags |
|------|------|----------------|
| DATA | 0x00 | END_STREAM (0x1), PADDED (0x8) |
| HEADERS | 0x01 | END_STREAM (0x1), END_HEADERS (0x4), PADDED (0x8), PRIORITY (0x20) |
| PRIORITY | 0x02 | - |
| RST_STREAM | 0x03 | - |
| SETTINGS | 0x04 | ACK (0x1) |
| PUSH_PROMISE | 0x05 | END_HEADERS (0x4), PADDED (0x8) |
| PING | 0x06 | ACK (0x1) |
| GOAWAY | 0x07 | - |
| WINDOW_UPDATE | 0x08 | - |
| CONTINUATION | 0x09 | END_HEADERS (0x4) |

### Connection Preface

Client must send exactly: `"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"` (24 bytes)

Followed immediately by a SETTINGS frame.

### HEADERS Frame Payload Structure

```
+---------------+
|Pad Length? (8)|  <- Only if PADDED flag set
+---------------+-----------------------------------------------+
|E|                 Stream Dependency? (31)                     |  <- Only if PRIORITY flag set
+-+-------------+-----------------------------------------------+
|  Weight? (8)  |  <- Only if PRIORITY flag set
+-+-------------+-----------------------------------------------+
|                   Header Block Fragment                     ...
+---------------------------------------------------------------+
|                           Padding                           ...
+---------------------------------------------------------------+
```

### CONTINUATION Handling

When HEADERS frame does not have END_HEADERS flag:
1. Buffer the header block fragment
2. Expect CONTINUATION frames on same stream
3. Accumulate fragments until END_HEADERS flag
4. Only then decode via HPAX

---

## HPACK Table Management

### Dual Tables Per Connection

Each HTTP/2 connection has **two independent HPACK contexts**:

1. **Server decode table**: Decodes headers sent by client (requests)
2. **Client decode table**: Decodes headers sent by server (responses)

```elixir
# When receiving HEADERS from client
{:ok, headers, new_table} = HPAX.decode(header_block, conn.server_decode_table)
conn = %{conn | server_decode_table: new_table}

# When receiving HEADERS from server
{:ok, headers, new_table} = HPAX.decode(header_block, conn.client_decode_table)
conn = %{conn | client_decode_table: new_table}
```

### SETTINGS-Driven Table Size (RFC 7540 Compliant)

Per RFC 7540, SETTINGS are applied **immediately on receipt** - the ACK is only confirmation that the peer received them. When a SETTINGS frame contains HEADER_TABLE_SIZE (0x1):

1. Apply immediately when received (don't wait for ACK)
2. The sender is advertising their decoder table size
3. Resize the appropriate table for decoding headers from that sender

```elixir
# Client sends SETTINGS with HEADER_TABLE_SIZE=8192
#   → Client's decoder accepts up to 8192 bytes
#   → We decode server→client headers with client_decode_table
#   → Resize client_decode_table to 8192

# Server sends SETTINGS with HEADER_TABLE_SIZE=4096
#   → Server's decoder accepts up to 4096 bytes
#   → We decode client→server headers with server_decode_table
#   → Resize server_decode_table to 4096
```

**Note**: ACK frames require no action - they simply confirm receipt.

### Error Handling

HPACK decode errors should:
1. Mark the stream as errored
2. Add to incomplete exchanges list
3. Continue processing other streams (don't fail entire connection)

---

## Test Fixtures

### HTTP/2 Capture Script

**File**: `test/fixtures/capture_http2_traffic.sh`

```bash
#!/bin/bash
# Capture HTTP/2 cleartext (prior-knowledge h2c) traffic for testing
# Requires: dumpcap, nghttp2 (nghttp client), Python 3 with hypercorn

set -euo pipefail

HTTP2_PORT="${HTTP2_PORT:-8900}"
OUTPUT_FILE="${1:-http2_sample.pcapng}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Platform detection for loopback interface
detect_loopback() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "lo0"
    else
        echo "lo"
    fi
}

INTERFACE="${2:-$(detect_loopback)}"

cleanup() {
    [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
    [[ -n "${DUMPCAP_PID:-}" ]] && kill -INT "$DUMPCAP_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 1. Start h2c server
echo "Starting HTTP/2 server on port $HTTP2_PORT..."
python3 "$SCRIPT_DIR/h2c_server.py" "$HTTP2_PORT" &
SERVER_PID=$!
sleep 2

# 2. Start capture
echo "Starting capture on interface $INTERFACE..."
dumpcap -i "$INTERFACE" -f "tcp port $HTTP2_PORT" -w "$OUTPUT_FILE" -q &
DUMPCAP_PID=$!
sleep 1

# 3. Generate traffic with nghttp (prior-knowledge h2c via --no-tls)
echo "Generating HTTP/2 traffic..."

# Simple requests
nghttp -v "http://127.0.0.1:$HTTP2_PORT/hello"
nghttp -v "http://127.0.0.1:$HTTP2_PORT/json"

# POST with body
echo "test body data" | nghttp -v -d - "http://127.0.0.1:$HTTP2_PORT/echo"

# Large response (to test multi-frame DATA)
nghttp -v "http://127.0.0.1:$HTTP2_PORT/large"

# Multiplexed requests (concurrent streams)
nghttp -v -m 3 \
  "http://127.0.0.1:$HTTP2_PORT/a" \
  "http://127.0.0.1:$HTTP2_PORT/b" \
  "http://127.0.0.1:$HTTP2_PORT/c"

# Request with trailers
nghttp -v -H "TE: trailers" "http://127.0.0.1:$HTTP2_PORT/with-trailers"

# 4. Wait and cleanup
sleep 1
echo "Capture saved to $OUTPUT_FILE"

# Also create .pcap version
if command -v editcap &>/dev/null; then
    pcap_file="${OUTPUT_FILE%.pcapng}.pcap"
    editcap -F pcap "$OUTPUT_FILE" "$pcap_file"
    echo "Also created $pcap_file"
fi
```

### HTTP/2 Server (h2c)

**File**: `test/fixtures/h2c_server.py`

```python
#!/usr/bin/env python3
"""
HTTP/2 cleartext (h2c) server for test fixture generation.
Supports prior-knowledge h2c (no Upgrade).

Requires: pip install hypercorn starlette h2

Run directly: python3 h2c_server.py 8900
Or via hypercorn: hypercorn h2c_server:app --bind 127.0.0.1:8900
"""

import sys
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, JSONResponse, StreamingResponse
from starlette.routing import Route


async def hello(request):
    return PlainTextResponse("Hello, HTTP/2!")


async def json_endpoint(request):
    return JSONResponse({
        "message": "Hello",
        "protocol": "h2c",
        "method": request.method
    })


async def echo(request):
    body = await request.body()
    return PlainTextResponse(
        body.decode() if body else "(empty body)",
        headers={"x-echo-length": str(len(body))}
    )


async def large_response(request):
    """Return a large response to test multi-frame DATA."""
    data = "x" * 32768  # 32KB response
    return PlainTextResponse(data)


async def with_trailers(request):
    """Response with trailing headers."""
    async def generate():
        yield b"Response body with trailers\n"

    return StreamingResponse(
        generate(),
        media_type="text/plain",
        headers={"trailer": "x-checksum"},
        # Note: Starlette doesn't support trailers directly,
        # but h2 server will handle them if configured
    )


routes = [
    Route("/hello", hello),
    Route("/json", json_endpoint),
    Route("/echo", echo, methods=["POST", "PUT"]),
    Route("/large", large_response),
    Route("/with-trailers", with_trailers),
    Route("/a", lambda r: PlainTextResponse("Response A")),
    Route("/b", lambda r: PlainTextResponse("Response B")),
    Route("/c", lambda r: PlainTextResponse("Response C")),
]

app = Starlette(routes=routes)


if __name__ == "__main__":
    import asyncio
    import hypercorn.asyncio
    import hypercorn.config

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8900

    config = hypercorn.config.Config()
    config.bind = [f"127.0.0.1:{port}"]
    config.h2_max_concurrent_streams = 100
    config.h2_initial_window_size = 65535

    print(f"Starting HTTP/2 (h2c) server on port {port}...")
    asyncio.run(hypercorn.asyncio.serve(app, config))
```

---

## Testing Strategy

### Unit Tests

**File**: `test/pcap_file_ex/http2/frame_test.exs`

- Frame header parsing (all types)
- Flag extraction (END_STREAM, END_HEADERS, PADDED, PRIORITY, ACK)
- Padding removal
- Priority field extraction
- Incomplete frame detection (`:need_more`)
- Invalid frame handling

**File**: `test/pcap_file_ex/http2/frame_buffer_test.exs`

- Cross-packet frame reassembly
- Connection preface stripping
- Multiple frames in single append
- Partial frame buffering

**File**: `test/pcap_file_ex/http2/headers_test.exs`

- Pseudo vs regular header separation
- Request detection (`:method`)
- Response detection (`:status`)
- Trailers detection (no pseudo-headers)
- 1xx informational detection

### Property Tests

**File**: `test/property_test/http2_property_test.exs`

- Frame parsing preserves length/stream_id
- Headers always separate pseudo-headers correctly
- FrameBuffer: append + parse_all == original frames
- CONTINUATION: fragmented headers decode same as single HEADERS

### Integration Tests

**File**: `test/integration/http2_integration_test.exs`

- Parse real HTTP/2 PCAP fixture
- Verify complete exchange count
- Verify incomplete exchange reasons
- Multiple concurrent streams
- Large DATA frames (multi-packet)
- Trailing headers

---

## Implementation Order

### Phase 1: Core Frame Infrastructure
1. `HTTP2.Frame` - Frame parsing with padding/priority extraction
2. `HTTP2.FrameBuffer` - Cross-packet reassembly with preface stripping
3. `HTTP2.Headers` - Pseudo/regular separation, trailer detection

### Phase 2: State Management
4. `HTTP2.Connection` - Dual HPACK tables, SETTINGS handling
5. `HTTP2.StreamState` - CONTINUATION buffering, 1xx responses, END_STREAM tracking

### Phase 3: Analysis Engine
6. `HTTP2.Analyzer` - Main reconstruction algorithm with RST/GOAWAY handling
7. `HTTP2.Exchange` - Complete request/response pair struct
8. `HTTP2.IncompleteExchange` - Partial exchange with termination reason

### Phase 4: Public API & Integration
9. `HTTP2` - Public module with `analyze/1`, `stream_exchanges/1`, `http2?/1`
10. `DecoderRegistry` - Register HTTP/2 matcher/decoder

### Phase 5: Test Infrastructure
11. `test/fixtures/h2c_server.py` - HTTP/2 cleartext server
12. `test/fixtures/capture_http2_traffic.sh` - Capture script
13. Generate `http2_sample.pcap` and `http2_sample.pcapng` fixtures

### Phase 6: Tests
14. Unit tests for Frame, FrameBuffer, Headers
15. Property tests for frame parsing invariants
16. Integration tests with real PCAP fixtures

---

## Files Summary

### New Files

| File | Description |
|------|-------------|
| `lib/pcap_file_ex/http2.ex` | Public API |
| `lib/pcap_file_ex/http2/frame.ex` | Frame parsing with padding/priority |
| `lib/pcap_file_ex/http2/frame_buffer.ex` | Cross-packet reassembly |
| `lib/pcap_file_ex/http2/headers.ex` | Headers struct with trailer support |
| `lib/pcap_file_ex/http2/stream_state.ex` | Enhanced stream state |
| `lib/pcap_file_ex/http2/connection.ex` | Dual HPACK tables + SETTINGS |
| `lib/pcap_file_ex/http2/analyzer.ex` | Main reconstruction |
| `lib/pcap_file_ex/http2/exchange.ex` | Complete exchange |
| `lib/pcap_file_ex/http2/incomplete_exchange.ex` | Partial exchange |
| `test/fixtures/capture_http2_traffic.sh` | Capture script |
| `test/fixtures/h2c_server.py` | HTTP/2 server |
| `test/pcap_file_ex/http2/frame_test.exs` | Frame unit tests |
| `test/pcap_file_ex/http2/frame_buffer_test.exs` | Buffer unit tests |
| `test/pcap_file_ex/http2/headers_test.exs` | Headers unit tests |
| `test/property_test/http2_property_test.exs` | Property tests |
| `test/integration/http2_integration_test.exs` | Integration tests |

### Modified Files

| File | Change |
|------|--------|
| `mix.exs` | Add `{:hpax, "~> 1.0"}` |
| `lib/pcap_file_ex/decoder_registry.ex` | Register HTTP/2 decoder |
| `test/support/generators.ex` | Add HTTP/2 generators |
