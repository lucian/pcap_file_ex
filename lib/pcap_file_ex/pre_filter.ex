defmodule PcapFileEx.PreFilter do
  @moduledoc """
  BPF-style pre-filtering in the Rust layer for high-performance packet filtering.

  This module provides filters that are applied in the Rust layer before packets
  are deserialized to Elixir terms, resulting in 10-100x performance improvements
  for selective filtering on large files.

  ## Important Notes

  **File Format Auto-Detection:**
  If you get an error like "Invalid field value: PcapHeader: wrong magic number",
  your file might be PCAPNG format despite having a `.pcap` extension. Use
  `PcapFileEx.open/1` for auto-detection instead of `Pcap.open/1` or `PcapNg.open/1`.

  ```elixir
  # ✓ RECOMMENDED: Auto-detect format
  {:ok, reader} = PcapFileEx.open("capture.pcap")

  # ✗ AVOID: Manual format selection (unless you're sure)
  {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")  # Fails if actually PCAPNG
  ```

  ## Filter Types

  ### IP Filters
  - `ip_source/1` - Match source IP address
  - `ip_dest/1` - Match destination IP address
  - `ip_source_cidr/1` - Match source IP in CIDR range
  - `ip_dest_cidr/1` - Match destination IP in CIDR range

  ### Port Filters
  - `port_source/1` - Match source port
  - `port_dest/1` - Match destination port
  - `port_source_range/2` - Match source port in range
  - `port_dest_range/2` - Match destination port in range

  ### Protocol Filters
  - `protocol/1` - Match protocol (tcp, udp, icmp, ipv4, ipv6, etc.)

  ### Size Filters
  - `size_min/1` - Match minimum packet size
  - `size_max/1` - Match maximum packet size
  - `size_range/2` - Match packet size in range

  ### Timestamp Filters
  - `timestamp_min/1` - Match packets after timestamp (Unix seconds)
  - `timestamp_max/1` - Match packets before timestamp (Unix seconds)

  ### Logical Operators
  - `all/1` - All filters must match (AND)
  - `any/1` - Any filter can match (OR)
  - `not_filter/1` - Invert filter (NOT)

  ## Examples

      # Filter TCP packets on port 80
      filters = [
        PcapFileEx.PreFilter.protocol("tcp"),
        PcapFileEx.PreFilter.port_dest(80)
      ]

      {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
      :ok = PcapFileEx.Pcap.set_filter(reader, filters)

      # Now reading will only return matching packets
      PcapFileEx.Stream.from_reader(reader)
      |> Enum.take(10)

      # Filter by IP range
      filters = [
        PcapFileEx.PreFilter.ip_source_cidr("192.168.1.0/24"),
        PcapFileEx.PreFilter.size_range(100, 1500)
      ]

      # Combine filters with logical operators
      filters = [
        PcapFileEx.PreFilter.any([
          PcapFileEx.PreFilter.port_dest(80),
          PcapFileEx.PreFilter.port_dest(443)
        ])
      ]

  ## Performance

  Pre-filters are significantly faster than post-processing filters because:
  - Packets are filtered in Rust before creating Elixir terms
  - No memory allocation for filtered-out packets
  - Reduced garbage collection pressure
  - Lower CPU usage (no unnecessary protocol parsing)

  For large files with selective filtering (e.g., "show me 10 packets on port 80
  from a 10GB capture"), pre-filters can be 10-100x faster than post-processing.
  """

  @type filter ::
          {:ip_source, String.t()}
          | {:ip_dest, String.t()}
          | {:ip_source_cidr, String.t()}
          | {:ip_dest_cidr, String.t()}
          | {:port_source, 0..65535}
          | {:port_dest, 0..65535}
          | {:port_source_range, 0..65535, 0..65535}
          | {:port_dest_range, 0..65535, 0..65535}
          | {:protocol, String.t()}
          | {:size_min, non_neg_integer()}
          | {:size_max, non_neg_integer()}
          | {:size_range, non_neg_integer(), non_neg_integer()}
          | {:timestamp_min, non_neg_integer()}
          | {:timestamp_max, non_neg_integer()}
          | {:and, [filter()]}
          | {:or, [filter()]}
          | {:not, filter()}

  @doc """
  Match source IP address.

  ## Examples

      PreFilter.ip_source("192.168.1.1")
  """
  @spec ip_source(String.t()) :: filter()
  def ip_source(ip) when is_binary(ip), do: {:ip_source, ip}

  @doc """
  Match destination IP address.

  ## Examples

      PreFilter.ip_dest("8.8.8.8")
  """
  @spec ip_dest(String.t()) :: filter()
  def ip_dest(ip) when is_binary(ip), do: {:ip_dest, ip}

  @doc """
  Match source IP in CIDR range.

  ## Examples

      PreFilter.ip_source_cidr("192.168.1.0/24")
      PreFilter.ip_source_cidr("2001:db8::/32")
  """
  @spec ip_source_cidr(String.t()) :: filter()
  def ip_source_cidr(cidr) when is_binary(cidr), do: {:ip_source_cidr, cidr}

  @doc """
  Match destination IP in CIDR range.

  ## Examples

      PreFilter.ip_dest_cidr("10.0.0.0/8")
  """
  @spec ip_dest_cidr(String.t()) :: filter()
  def ip_dest_cidr(cidr) when is_binary(cidr), do: {:ip_dest_cidr, cidr}

  @doc """
  Match source port.

  ## Examples

      PreFilter.port_source(8080)
  """
  @spec port_source(0..65535) :: filter()
  def port_source(port) when is_integer(port) and port >= 0 and port <= 65535,
    do: {:port_source, port}

  @doc """
  Match destination port.

  ## Examples

      PreFilter.port_dest(80)
      PreFilter.port_dest(443)
  """
  @spec port_dest(0..65535) :: filter()
  def port_dest(port) when is_integer(port) and port >= 0 and port <= 65535,
    do: {:port_dest, port}

  @doc """
  Match source port in range.

  ## Examples

      PreFilter.port_source_range(8000, 9000)
  """
  @spec port_source_range(0..65535, 0..65535) :: filter()
  def port_source_range(min, max)
      when is_integer(min) and is_integer(max) and min >= 0 and max <= 65535,
      do: {:port_source_range, min, max}

  @doc """
  Match destination port in range.

  ## Examples

      PreFilter.port_dest_range(1024, 65535)
  """
  @spec port_dest_range(0..65535, 0..65535) :: filter()
  def port_dest_range(min, max)
      when is_integer(min) and is_integer(max) and min >= 0 and max <= 65535,
      do: {:port_dest_range, min, max}

  @doc """
  Match protocol.

  Supported protocols: tcp, udp, icmp, icmpv6, ipv4, ipv6

  ## Examples

      PreFilter.protocol("tcp")
      PreFilter.protocol("udp")
      PreFilter.protocol("icmp")
  """
  @spec protocol(String.t()) :: filter()
  def protocol(proto) when is_binary(proto), do: {:protocol, String.downcase(proto)}

  @doc """
  Match minimum packet size (original length).

  ## Examples

      PreFilter.size_min(100)
  """
  @spec size_min(non_neg_integer()) :: filter()
  def size_min(bytes) when is_integer(bytes) and bytes >= 0, do: {:size_min, bytes}

  @doc """
  Match maximum packet size (original length).

  ## Examples

      PreFilter.size_max(1500)
  """
  @spec size_max(non_neg_integer()) :: filter()
  def size_max(bytes) when is_integer(bytes) and bytes >= 0, do: {:size_max, bytes}

  @doc """
  Match packet size in range (original length).

  ## Examples

      PreFilter.size_range(100, 1500)
  """
  @spec size_range(non_neg_integer(), non_neg_integer()) :: filter()
  def size_range(min, max) when is_integer(min) and is_integer(max) and min >= 0,
    do: {:size_range, min, max}

  @doc """
  Match packets after timestamp (Unix seconds).

  ## Examples

      PreFilter.timestamp_min(1730732400)
  """
  @spec timestamp_min(non_neg_integer()) :: filter()
  def timestamp_min(secs) when is_integer(secs) and secs >= 0, do: {:timestamp_min, secs}

  @doc """
  Match packets before timestamp (Unix seconds).

  ## Examples

      PreFilter.timestamp_max(1730818800)
  """
  @spec timestamp_max(non_neg_integer()) :: filter()
  def timestamp_max(secs) when is_integer(secs) and secs >= 0, do: {:timestamp_max, secs}

  @doc """
  All filters must match (AND).

  ## Examples

      PreFilter.all([
        PreFilter.protocol("tcp"),
        PreFilter.port_dest(80)
      ])
  """
  @spec all([filter()]) :: filter()
  def all(filters) when is_list(filters), do: {:and, filters}

  @doc """
  Any filter can match (OR).

  ## Examples

      PreFilter.any([
        PreFilter.port_dest(80),
        PreFilter.port_dest(443)
      ])
  """
  @spec any([filter()]) :: filter()
  def any(filters) when is_list(filters), do: {:or, filters}

  @doc """
  Invert filter (NOT).

  ## Examples

      PreFilter.not_filter(PreFilter.protocol("tcp"))
  """
  @spec not_filter(filter()) :: filter()
  def not_filter(filter), do: {:not, filter}
end
