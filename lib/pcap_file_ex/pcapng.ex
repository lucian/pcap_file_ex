defmodule PcapFileEx.PcapNg do
  @moduledoc """
  Reader for PCAPNG (next-generation) format files.
  """

  alias PcapFileEx.{Interface, Native, Packet}

  @type t :: %__MODULE__{
          reference: reference(),
          path: String.t()
        }

  defstruct [:reference, :path]

  @doc """
  Opens a PCAPNG file for reading.

  ## Examples

      iex> {:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")
      iex> is_struct(reader, PcapFileEx.PcapNg)
      true
  """
  @spec open(Path.t()) :: {:ok, t()} | {:error, String.t()}
  def open(path) when is_binary(path) do
    case Native.pcapng_open(path) do
      {:error, reason} ->
        {:error, reason}

      reference when is_reference(reference) ->
        {:ok, %__MODULE__{reference: reference, path: path}}
    end
  end

  @doc """
  Closes the PCAPNG reader and releases resources.
  """
  @spec close(t()) :: :ok
  def close(%__MODULE__{reference: reference}) do
    Native.pcapng_close(reference)
  end

  @doc """
  Sets pre-filters on the reader for high-performance filtering in the Rust layer.

  Filters are applied before packets are deserialized to Elixir, providing
  10-100x performance improvement for selective filtering on large files.

  See `PcapFileEx.PreFilter` for available filter types.

  ## Examples

      {:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")

      filters = [
        PcapFileEx.PreFilter.protocol("tcp"),
        PcapFileEx.PreFilter.port_dest(80)
      ]

      :ok = PcapFileEx.PcapNg.set_filter(reader, filters)

      # Now next_packet will only return matching packets
      {:ok, packet} = PcapFileEx.PcapNg.next_packet(reader)
  """
  @spec set_filter(t(), [PcapFileEx.PreFilter.filter()]) :: :ok | {:error, String.t()}
  def set_filter(%__MODULE__{reference: reference}, filters) when is_list(filters) do
    Native.pcapng_set_filter(reference, filters)
  end

  @doc """
  Clears all pre-filters from the reader.

  ## Examples

      {:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")
      :ok = PcapFileEx.PcapNg.set_filter(reader, [...])
      :ok = PcapFileEx.PcapNg.clear_filter(reader)
  """
  @spec clear_filter(t()) :: :ok | {:error, String.t()}
  def clear_filter(%__MODULE__{reference: reference}) do
    Native.pcapng_clear_filter(reference)
  end

  @doc """
  Reads the next packet from the PCAPNG file.

  This automatically skips non-packet blocks (like Section Header,
  Interface Description, etc.) and returns only packet data.

  Returns `{:ok, packet}` if a packet was read, `:eof` if the end of file
  was reached, or `{:error, reason}` if an error occurred.

  ## Options

  - `:hosts_map` - Map of IP address strings to hostname strings for endpoint resolution

  ## Examples

      {:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")
      {:ok, packet} = PcapFileEx.PcapNg.next_packet(reader)
      IO.inspect(packet.timestamp)

      # With hosts mapping
      hosts = %{"192.168.1.1" => "gateway", "10.0.0.1" => "server"}
      {:ok, packet} = PcapFileEx.PcapNg.next_packet(reader, hosts_map: hosts)
  """
  @spec next_packet(t()) :: {:ok, Packet.t()} | :eof | {:error, String.t()}
  def next_packet(reader), do: next_packet(reader, [])

  @spec next_packet(t(), keyword()) :: {:ok, Packet.t()} | :eof | {:error, String.t()}
  def next_packet(%__MODULE__{reference: reference}, opts) do
    case Native.pcapng_next_packet(reference) do
      nil ->
        :eof

      {:error, reason} ->
        {:error, reason}

      packet_map when is_map(packet_map) ->
        {:ok, Packet.from_map(packet_map, opts)}
    end
  end

  @doc """
  Reads all packets from the PCAPNG file into a list.

  This loads all packets into memory, so be careful with large files.

  Returns `{:ok, packets}` on success or `{:error, reason}` if a packet
  fails to parse. On error, the file is still properly closed.

  ## Options

  - `:hosts_map` - Map of IP address strings to hostname strings for endpoint resolution

  ## Examples

      {:ok, packets} = PcapFileEx.PcapNg.read_all("capture.pcapng")
      Enum.count(packets)

      # With hosts mapping
      hosts = %{"192.168.1.1" => "gateway"}
      {:ok, packets} = PcapFileEx.PcapNg.read_all("capture.pcapng", hosts_map: hosts)
  """
  @spec read_all(Path.t()) :: {:ok, [Packet.t()]} | {:error, String.t()}
  def read_all(path), do: read_all(path, [])

  @spec read_all(Path.t(), keyword()) :: {:ok, [Packet.t()]} | {:error, String.t()}
  def read_all(path, opts) do
    case open(path) do
      {:ok, reader} ->
        result = read_all_packets(reader, [], opts)
        close(reader)

        case result do
          {:ok, packets} -> {:ok, Enum.reverse(packets)}
          {:error, _reason} = error -> error
        end

      {:error, _reason} = error ->
        error
    end
  end

  @doc """
  Returns metadata for all interfaces discovered in the PCAPNG file.

  The interface list is populated lazily as blocks are encountered during reads.
  Calling `next_packet/1` at least once ensures interface metadata is available.
  """
  @spec interfaces(t()) :: {:ok, [Interface.t()]} | {:error, String.t()}
  def interfaces(%__MODULE__{reference: reference}) do
    case Native.pcapng_interfaces(reference) do
      {:error, reason} ->
        {:error, reason}

      interfaces when is_list(interfaces) ->
        {:ok, Enum.map(interfaces, &Interface.from_map/1)}
    end
  end

  defp read_all_packets(reader, acc, opts) do
    case next_packet(reader, opts) do
      {:ok, packet} -> read_all_packets(reader, [packet | acc], opts)
      :eof -> {:ok, acc}
      {:error, reason} -> {:error, reason}
    end
  end
end
