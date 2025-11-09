defmodule PcapFileEx.PropertyGenerators do
  @moduledoc """
  StreamData generators for property-based testing of PcapFileEx.

  This module provides generators for all core data types:
  - Timestamps (with boundary cases)
  - Packets (with valid structures)
  - DateTime values
  - Ranges (for filters)
  - Protocols

  All generators produce valid data structures that conform to the
  type specifications and invariants of the library.
  """

  use ExUnitProperties

  alias PcapFileEx.{Packet, Timestamp}

  # ============================================================================
  # Timestamp Generators
  # ============================================================================

  @doc """
  Generates random valid timestamps.

  Produces timestamps with:
  - secs: 0..3_000_000_000 (covers 1970 to ~2065)
  - nanos: 0..999_999_999 (valid nanosecond range)
  """
  def timestamp_generator do
    gen all secs <- integer(0..3_000_000_000),
            nanos <- integer(0..999_999_999) do
      Timestamp.new(secs, nanos)
    end
  end

  @doc """
  Generates timestamps at boundary conditions.

  Includes edge cases:
  - Epoch (0, 0)
  - Maximum nanosecond component
  - Year 2038 problem (32-bit signed int max)
  - Far future timestamps
  """
  def timestamp_boundary_generator do
    member_of([
      Timestamp.new(0, 0),
      # Epoch
      Timestamp.new(0, 999_999_999),
      # Almost 1 second
      Timestamp.new(1, 0),
      # First second
      Timestamp.new(2_147_483_647, 0),
      # Year 2038 (32-bit max)
      Timestamp.new(2_147_483_647, 999_999_999),
      # Max 32-bit with max nanos
      Timestamp.new(1_000_000_000, 0),
      # Year ~2001
      Timestamp.new(1_500_000_000, 500_000_000),
      # ~2017 mid-second
      Timestamp.new(3_000_000_000, 0)
      # Far future ~2065
    ])
  end

  @doc """
  Generates timestamps combining regular and boundary cases.

  Weighted 80% regular, 20% boundary cases for better edge case coverage.
  """
  def mixed_timestamp_generator do
    frequency([
      {8, timestamp_generator()},
      {2, timestamp_boundary_generator()}
    ])
  end

  @doc """
  Generates valid DateTime values for conversion testing.

  Range: 0..2_000_000_000 seconds (1970 to ~2033)
  Microsecond precision (DateTime's maximum)
  """
  def datetime_generator do
    gen all secs <- integer(0..2_000_000_000),
            micros <- integer(0..999_999) do
      DateTime.from_unix!(secs, :second)
      |> DateTime.add(micros, :microsecond)
    end
  end

  # ============================================================================
  # Packet Data Generators
  # ============================================================================

  @doc """
  Generates random binary data for packet payloads.

  Size range: 14..9000 bytes (typical Ethernet frame sizes)
  - 14 bytes: Minimum Ethernet frame
  - 1500 bytes: Standard MTU
  - 9000 bytes: Jumbo frames
  """
  def packet_data_generator do
    gen all size <- integer(14..9000) do
      <<rand_bytes::binary-size(size)>> = :crypto.strong_rand_bytes(size)
      rand_bytes
    end
  end

  @doc """
  Generates compact packet data (smaller, faster for most tests).

  Size range: 14..1500 bytes (standard Ethernet frames)
  """
  def compact_packet_data_generator do
    gen all size <- integer(14..1500) do
      <<rand_bytes::binary-size(size)>> = :crypto.strong_rand_bytes(size)
      rand_bytes
    end
  end

  @doc """
  Generates valid datalink type strings.
  """
  def datalink_generator do
    member_of([
      "ethernet",
      "raw",
      "ipv4",
      "ipv6",
      "linux_sll",
      "linux_sll2",
      "null",
      "loop",
      "ppp"
    ])
  end

  @doc """
  Generates raw packet maps as returned by the Rust NIF.

  Ensures invariants:
  - orig_len >= byte_size(data)
  - timestamp_nanos in valid range
  - All required fields present
  """
  def pcap_packet_map_generator do
    gen all timestamp_secs <- integer(0..2_000_000_000),
            timestamp_nanos <- integer(0..999_999_999),
            data <- compact_packet_data_generator(),
            datalink <- datalink_generator(),
            # Generate orig_len offset for truncated captures
            truncation_offset <- integer(0..1000) do
      data_list = :binary.bin_to_list(data)
      data_size = byte_size(data)

      # orig_len can be >= data size (truncated captures)
      # If offset > 0, this is a truncated capture
      orig_len = data_size + truncation_offset

      %{
        timestamp_secs: timestamp_secs,
        timestamp_nanos: timestamp_nanos,
        orig_len: orig_len,
        data: data_list,
        datalink: datalink
      }
    end
  end

  @doc """
  Generates valid Packet structs.
  """
  def packet_generator do
    gen all packet_map <- pcap_packet_map_generator() do
      Packet.from_map(packet_map)
    end
  end

  @doc """
  Generates lists of packets.

  Options:
  - :min_length - Minimum list length (default: 0)
  - :max_length - Maximum list length (default: 100)
  """
  def packet_list_generator(opts \\ []) do
    min_length = Keyword.get(opts, :min_length, 0)
    max_length = Keyword.get(opts, :max_length, 100)

    list_of(packet_generator(), min_length: min_length, max_length: max_length)
  end

  @doc """
  Generates non-empty lists of packets.
  """
  def non_empty_packet_list_generator(opts \\ []) do
    max_length = Keyword.get(opts, :max_length, 100)

    list_of(packet_generator(), min_length: 1, max_length: max_length)
  end

  # ============================================================================
  # Filter-related Generators
  # ============================================================================

  @doc """
  Generates size ranges for packet filtering.

  Returns min..max ranges where min < max
  """
  def size_range_generator do
    gen all min_size <- integer(0..5000),
            max_size <- integer((min_size + 1)..10000) do
      min_size..max_size
    end
  end

  @doc """
  Generates positive integers for size thresholds.
  """
  def size_threshold_generator do
    integer(1..10000)
  end

  @doc """
  Generates time ranges for packet filtering.

  Returns {start_dt, end_dt} tuples with end > start
  Duration: 1 second to 1 day
  """
  def time_range_generator do
    gen all start_secs <- integer(1_000_000_000..2_000_000_000),
            duration_secs <- integer(1..86400) do
      start_dt = DateTime.from_unix!(start_secs, :second)
      end_dt = DateTime.add(start_dt, duration_secs, :second)
      {start_dt, end_dt}
    end
  end

  @doc """
  Generates protocol atoms from known protocols.
  """
  def protocol_generator do
    member_of([
      :ether,
      :ipv4,
      :ipv6,
      :tcp,
      :udp,
      :icmp,
      :http,
      :dns,
      :arp
    ])
  end

  # ============================================================================
  # Endpoint Generators (for decoded packets)
  # ============================================================================

  @doc """
  Generates valid IPv4 address strings.
  """
  def ipv4_string_generator do
    gen all a <- integer(0..255),
            b <- integer(0..255),
            c <- integer(0..255),
            d <- integer(0..255) do
      "#{a}.#{b}.#{c}.#{d}"
    end
  end

  @doc """
  Generates valid port numbers (0..65535).
  """
  def port_generator do
    integer(0..65535)
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  @doc """
  Generates a value from any generator (useful for testing).
  """
  def generate(generator) do
    Enum.take(generator, 1) |> hd()
  end
end
