defmodule PcapFileEx.Pcap do
  @moduledoc """
  Reader for PCAP (legacy) format files.
  """

  alias PcapFileEx.{Header, Native, Packet}

  @type t :: %__MODULE__{
          reference: reference(),
          header: Header.t(),
          path: String.t()
        }

  defstruct [:reference, :header, :path]

  @doc """
  Opens a PCAP file for reading.

  ## Examples

      iex> {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
      iex> reader.header.datalink
      "ethernet"
  """
  @spec open(Path.t()) :: {:ok, t()} | {:error, String.t()}
  def open(path) when is_binary(path) do
    case Native.pcap_open(path) do
      {:error, reason} ->
        {:error, reason}

      reference when is_reference(reference) ->
        case Native.pcap_get_header(reference) do
          header_map when is_map(header_map) ->
            {:ok,
             %__MODULE__{
               reference: reference,
               header: Header.from_map(header_map),
               path: path
             }}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  @doc """
  Closes the PCAP reader and releases resources.
  """
  @spec close(t()) :: :ok
  def close(%__MODULE__{reference: reference}) do
    Native.pcap_close(reference)
  end

  @doc """
  Sets pre-filters on the reader for high-performance filtering in the Rust layer.

  Filters are applied before packets are deserialized to Elixir, providing
  10-100x performance improvement for selective filtering on large files.

  See `PcapFileEx.PreFilter` for available filter types.

  ## Examples

      {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")

      filters = [
        PcapFileEx.PreFilter.protocol("tcp"),
        PcapFileEx.PreFilter.port_dest(80)
      ]

      :ok = PcapFileEx.Pcap.set_filter(reader, filters)

      # Now next_packet will only return matching packets
      {:ok, packet} = PcapFileEx.Pcap.next_packet(reader)
  """
  @spec set_filter(t(), [PcapFileEx.PreFilter.filter()]) :: :ok | {:error, String.t()}
  def set_filter(%__MODULE__{reference: reference}, filters) when is_list(filters) do
    Native.pcap_set_filter(reference, filters)
  end

  @doc """
  Clears all pre-filters from the reader.

  ## Examples

      {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
      :ok = PcapFileEx.Pcap.set_filter(reader, [...])
      :ok = PcapFileEx.Pcap.clear_filter(reader)
  """
  @spec clear_filter(t()) :: :ok | {:error, String.t()}
  def clear_filter(%__MODULE__{reference: reference}) do
    Native.pcap_clear_filter(reference)
  end

  @doc """
  Reads the next packet from the PCAP file.

  Returns `{:ok, packet}` if a packet was read, `:eof` if the end of file
  was reached, or `{:error, reason}` if an error occurred.

  ## Examples

      {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
      {:ok, packet} = PcapFileEx.Pcap.next_packet(reader)
      IO.inspect(packet.timestamp)
  """
  @spec next_packet(t()) :: {:ok, Packet.t()} | :eof | {:error, String.t()}
  def next_packet(%__MODULE__{reference: reference}) do
    case Native.pcap_next_packet(reference) do
      nil ->
        :eof

      {:error, reason} ->
        {:error, reason}

      packet_map when is_map(packet_map) ->
        {:ok, Packet.from_map(packet_map)}
    end
  end

  @doc """
  Reads all packets from the PCAP file into a list.

  This loads all packets into memory, so be careful with large files.

  Returns `{:ok, packets}` on success or `{:error, reason}` if a packet
  fails to parse. On error, the file is still properly closed.

  ## Examples

      {:ok, packets} = PcapFileEx.Pcap.read_all("capture.pcap")
      Enum.count(packets)
  """
  @spec read_all(Path.t()) :: {:ok, [Packet.t()]} | {:error, String.t()}
  def read_all(path) do
    case open(path) do
      {:ok, reader} ->
        result = read_all_packets(reader, [])
        close(reader)

        case result do
          {:ok, packets} -> {:ok, Enum.reverse(packets)}
          {:error, _reason} = error -> error
        end

      {:error, _reason} = error ->
        error
    end
  end

  defp read_all_packets(reader, acc) do
    case next_packet(reader) do
      {:ok, packet} -> read_all_packets(reader, [packet | acc])
      :eof -> {:ok, acc}
      {:error, reason} -> {:error, reason}
    end
  end
end
