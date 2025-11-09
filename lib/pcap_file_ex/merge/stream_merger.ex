defmodule PcapFileEx.Merge.StreamMerger do
  @moduledoc """
  Core streaming merge implementation using priority queue.

  This module implements the low-level merge logic that combines multiple
  packet streams in chronological order using a min-heap priority queue.

  ## Algorithm

  1. Open all files and create individual streams
  2. Initialize min-heap with first packet from each file
  3. Loop:
     - Pop minimum packet from heap (earliest timestamp)
     - Emit packet to output stream
     - Read next packet from same file
     - Push new packet onto heap
  4. Continue until all files are exhausted

  ## Performance

  - Memory: O(N files) - only one packet buffered per file
  - Time: O(M log N) where M = total packets, N = number of files
  - Streaming: Constant memory regardless of file sizes
  """

  alias PcapFileEx.{Format, Pcap, PcapNg}
  alias PcapFileEx.Merge.{Heap, InterfaceMapper}

  @type error_mode :: :skip | :halt | :collect
  @type file_state :: %{
          reader: Pcap.t() | PcapNg.t(),
          path: String.t(),
          file_index: non_neg_integer(),
          packet_index: non_neg_integer(),
          format: :pcap | :pcapng,
          eof: boolean(),
          skip_count: non_neg_integer(),
          last_error: {String.t(), non_neg_integer()} | nil
        }

  @doc """
  Creates a merged stream from multiple file paths.

  ## Parameters

  - `paths` - List of file paths to merge
  - `annotate` - Whether to include source metadata with each packet
  - `error_mode` - How to handle errors: `:skip`, `:halt`, or `:collect`

  ## Returns

  A stream that emits packets in chronological order. The stream item type
  depends on the options:

  - Base case: `%Packet{}`
  - With annotation: `{%Packet{}, metadata}`
  - With :collect mode: `{:ok, item} | {:error, meta}`
  - With :skip mode: `%Packet{} | {:skipped_packet, meta}`

  ## Examples

      stream = PcapFileEx.Merge.StreamMerger.merge(["s1.pcap", "s2.pcap"], false, :halt)
      packets = Enum.to_list(stream)
  """
  @spec merge([String.t()], boolean(), error_mode()) :: Enumerable.t()
  def merge(paths, annotate, error_mode) do
    Stream.resource(
      fn -> initialize_merge(paths) end,
      fn state -> next_packet(state, annotate, error_mode) end,
      fn state -> cleanup_merge(state) end
    )
  end

  # Private functions

  defp initialize_merge(paths) do
    # Open all files and create initial state
    file_states =
      paths
      |> Enum.with_index()
      |> Enum.map(fn {path, index} ->
        format = Format.detect(path)

        reader =
          case format do
            :pcap ->
              {:ok, r} = Pcap.open(path)
              r

            :pcapng ->
              {:ok, r} = PcapNg.open(path)
              r
          end

        %{
          reader: reader,
          path: path,
          file_index: index,
          packet_index: 0,
          format: format,
          eof: false,
          skip_count: 0,
          last_error: nil
        }
      end)

    # Build interface ID mapping for PCAPNG files
    interface_mapping = InterfaceMapper.build_mapping(file_states)

    # Initialize heap with first packet from each file
    initial_heap =
      file_states
      |> Enum.reduce(Heap.new(), fn file_state, heap ->
        case read_next_packet(file_state) do
          {:ok, packet, _new_state} ->
            # Remap interface ID before pushing to heap
            {remapped_packet, orig_id} =
              InterfaceMapper.remap_packet(packet, file_state.file_index, interface_mapping)

            Heap.push(
              heap,
              remapped_packet,
              file_state.file_index,
              file_state.packet_index,
              orig_id
            )

          {:eof, _new_state} ->
            heap

          {:error, _, _new_state} ->
            heap
        end
      end)

    %{
      heap: initial_heap,
      files: file_states,
      total_emitted: 0,
      should_halt: false,
      interface_mapping: interface_mapping
    }
  end

  defp next_packet(state, annotate, error_mode) do
    if Heap.empty?(state.heap) or state.should_halt do
      {:halt, state}
    else
      # Pop minimum packet from heap (with original interface ID)
      {packet, file_idx, _pkt_idx, orig_iface_id, new_heap} = Heap.pop(state.heap)

      # Get file state for this packet
      file_state = Enum.at(state.files, file_idx)

      # Read next packet from the same file
      case read_next_packet(file_state) do
        {:ok, next_packet, new_file_state} ->
          # Success - remap interface ID, reset skip count, push to heap, emit current packet
          {remapped_packet, next_orig_id} =
            InterfaceMapper.remap_packet(next_packet, file_idx, state.interface_mapping)

          updated_heap =
            Heap.push(
              new_heap,
              remapped_packet,
              file_idx,
              new_file_state.packet_index,
              next_orig_id
            )

          updated_file_state = %{new_file_state | skip_count: 0, last_error: nil}
          updated_files = List.replace_at(state.files, file_idx, updated_file_state)
          item = build_output_item(packet, file_state, orig_iface_id, annotate, error_mode)

          new_state = %{
            state
            | heap: updated_heap,
              files: updated_files,
              total_emitted: state.total_emitted + 1
          }

          {[item], new_state}

        {:eof, new_file_state} ->
          # EOF - just emit current packet, don't push anything
          updated_files = List.replace_at(state.files, file_idx, new_file_state)
          item = build_output_item(packet, file_state, orig_iface_id, annotate, error_mode)

          new_state = %{
            state
            | heap: new_heap,
              files: updated_files,
              total_emitted: state.total_emitted + 1
          }

          {[item], new_state}

        {:error, reason, new_file_state} ->
          # ERROR - emit successful packet, then handle error based on mode
          success_item =
            build_output_item(packet, file_state, orig_iface_id, annotate, error_mode)

          # Update file state with error info
          updated_skip_count = new_file_state.skip_count + 1

          updated_file_state = %{
            new_file_state
            | skip_count: updated_skip_count,
              last_error: {reason, new_file_state.packet_index - 1}
          }

          updated_files = List.replace_at(state.files, file_idx, updated_file_state)

          # Generate error item based on mode
          error_item = emit_error_item(error_mode, reason, updated_file_state, annotate)

          case error_item do
            :halt_signal ->
              # Halt mode - emit successful packet, then signal halt
              new_state = %{
                state
                | heap: new_heap,
                  files: updated_files,
                  total_emitted: state.total_emitted + 1,
                  should_halt: true
              }

              {[success_item], new_state}

            error_tuple ->
              # Skip or collect mode - emit both successful packet and error
              new_state = %{
                state
                | heap: new_heap,
                  files: updated_files,
                  total_emitted: state.total_emitted + 1
              }

              {[success_item, error_tuple], new_state}
          end
      end
    end
  end

  defp cleanup_merge(state) do
    # Close all file readers
    Enum.each(state.files, fn file_state ->
      case file_state.format do
        :pcap -> Pcap.close(file_state.reader)
        :pcapng -> PcapNg.close(file_state.reader)
      end
    end)

    :ok
  end

  defp read_next_packet(file_state) do
    if file_state.eof do
      {:eof, file_state}
    else
      result =
        case file_state.format do
          :pcap -> Pcap.next_packet(file_state.reader)
          :pcapng -> PcapNg.next_packet(file_state.reader)
        end

      case result do
        {:ok, packet} ->
          new_state = %{file_state | packet_index: file_state.packet_index + 1}
          {:ok, packet, new_state}

        :eof ->
          new_state = %{file_state | eof: true}
          {:eof, new_state}

        {:error, reason} ->
          new_state = %{file_state | packet_index: file_state.packet_index + 1}
          {:error, reason, new_state}
      end
    end
  end

  defp build_output_item(packet, file_state, orig_iface_id, annotate, error_mode) do
    # Build base item (packet or annotated tuple)
    base_item =
      if annotate do
        # Base metadata
        metadata = %{
          source_file: file_state.path,
          file_index: file_state.file_index,
          packet_index: file_state.packet_index
        }

        # Add interface IDs for PCAPNG files only
        metadata =
          if file_state.format == :pcapng and not is_nil(orig_iface_id) do
            metadata
            |> Map.put(:original_interface_id, orig_iface_id)
            |> Map.put(:remapped_interface_id, packet.interface_id)
          else
            metadata
          end

        {packet, metadata}
      else
        packet
      end

    # Wrap in error tuple if using :collect mode
    case error_mode do
      :collect -> {:ok, base_item}
      _ -> base_item
    end
  end

  defp emit_error_item(error_mode, reason, file_state, annotate) do
    case error_mode do
      :skip ->
        # Emit skip metadata with consecutive count
        # Note: packet_index in last_error is the failed packet's index
        {_last_reason, failed_packet_idx} = file_state.last_error

        {:skipped_packet,
         %{
           count: file_state.skip_count,
           last_error: %{
             source_file: file_state.path,
             packet_index: failed_packet_idx,
             reason: reason
           }
         }}

      :halt ->
        # Signal that stream should halt
        :halt_signal

      :collect ->
        # Emit error tuple (potentially nested with annotation)
        {_last_reason, failed_packet_idx} = file_state.last_error

        error_metadata = %{
          source_file: file_state.path,
          packet_index: failed_packet_idx,
          reason: reason
        }

        # If annotation is enabled, we need to handle nesting
        # For :collect + annotate: {:error, {error_meta, %{file_index: ...}}}
        # For :collect only: {:error, error_meta}
        if annotate do
          # Add file_index to error metadata for consistency with success path
          extended_metadata =
            Map.merge(error_metadata, %{
              file_index: file_state.file_index
            })

          {:error, extended_metadata}
        else
          {:error, error_metadata}
        end
    end
  end
end
