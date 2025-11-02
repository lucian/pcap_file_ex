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

  ## Examples

      {:ok, packets} = PcapFileEx.Pcap.read_all("capture.pcap")
      Enum.count(packets)
  """
  @spec read_all(Path.t()) :: {:ok, [Packet.t()]} | {:error, String.t()}
  def read_all(path) do
    with {:ok, reader} <- open(path) do
      packets = read_all_packets(reader, [])
      close(reader)
      {:ok, Enum.reverse(packets)}
    end
  end

  defp read_all_packets(reader, acc) do
    case next_packet(reader) do
      {:ok, packet} -> read_all_packets(reader, [packet | acc])
      :eof -> acc
      {:error, _} -> acc
    end
  end
end
