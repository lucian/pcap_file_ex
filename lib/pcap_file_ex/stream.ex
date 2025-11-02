defmodule PcapFileEx.Stream do
  @moduledoc """
  Stream protocol implementation for lazy packet reading.
  """

  alias PcapFileEx.Pcap

  @doc """
  Creates a lazy stream of packets from a PCAP file.

  The stream automatically handles opening and closing the file.

  ## Examples

      PcapFileEx.Stream.packets("capture.pcap")
      |> Stream.filter(fn packet -> byte_size(packet.data) > 1000 end)
      |> Enum.take(10)
  """
  @spec packets(Path.t()) :: Enumerable.t()
  def packets(path) do
    Stream.resource(
      # Start function: open the file
      fn ->
        case Pcap.open(path) do
          {:ok, reader} -> reader
          {:error, reason} -> raise "Failed to open PCAP file: #{reason}"
        end
      end,
      # Next function: read packets
      fn reader ->
        case Pcap.next_packet(reader) do
          {:ok, packet} -> {[packet], reader}
          :eof -> {:halt, reader}
          {:error, reason} -> raise "Failed to read packet: #{reason}"
        end
      end,
      # End function: close the file
      fn reader -> Pcap.close(reader) end
    )
  end

  @doc """
  Creates a lazy stream of packets from an already opened reader.

  This does NOT automatically close the reader when done.

  ## Examples

      {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")

      PcapFileEx.Stream.from_reader(reader)
      |> Enum.take(10)

      PcapFileEx.Pcap.close(reader)
  """
  @spec from_reader(Pcap.t()) :: Enumerable.t()
  def from_reader(reader) do
    Stream.resource(
      fn -> reader end,
      fn reader ->
        case Pcap.next_packet(reader) do
          {:ok, packet} -> {[packet], reader}
          :eof -> {:halt, reader}
          {:error, reason} -> raise "Failed to read packet: #{reason}"
        end
      end,
      fn _reader -> :ok end
    )
  end
end
