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
  Reads the next packet from the PCAPNG file.

  This automatically skips non-packet blocks (like Section Header,
  Interface Description, etc.) and returns only packet data.

  Returns `{:ok, packet}` if a packet was read, `:eof` if the end of file
  was reached, or `{:error, reason}` if an error occurred.

  ## Examples

      {:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")
      {:ok, packet} = PcapFileEx.PcapNg.next_packet(reader)
      IO.inspect(packet.timestamp)
  """
  @spec next_packet(t()) :: {:ok, Packet.t()} | :eof | {:error, String.t()}
  def next_packet(%__MODULE__{reference: reference}) do
    case Native.pcapng_next_packet(reference) do
      nil ->
        :eof

      {:error, reason} ->
        {:error, reason}

      packet_map when is_map(packet_map) ->
        {:ok, Packet.from_map(packet_map)}
    end
  end

  @doc """
  Reads all packets from the PCAPNG file into a list.

  This loads all packets into memory, so be careful with large files.

  ## Examples

      {:ok, packets} = PcapFileEx.PcapNg.read_all("capture.pcapng")
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

  defp read_all_packets(reader, acc) do
    case next_packet(reader) do
      {:ok, packet} -> read_all_packets(reader, [packet | acc])
      :eof -> acc
      {:error, _} -> acc
    end
  end
end
