defmodule PcapFileEx do
  @moduledoc """
  Elixir wrapper for parsing PCAP and PCAPNG network capture files.

  This library provides functionality to read packet capture files commonly used
  with tools like Wireshark, tcpdump, and dumpcap.

  ## Examples

      # Open and read a PCAP file
      {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
      IO.inspect(reader.header)

      # Read packets one at a time
      {:ok, packet} = PcapFileEx.Pcap.next_packet(reader)
      IO.inspect(packet.timestamp)
      IO.inspect(byte_size(packet.data))

      # Read all packets at once
      {:ok, packets} = PcapFileEx.read_all("capture.pcap")
      Enum.each(packets, fn packet ->
        IO.puts("Packet at \#{packet.timestamp}: \#{byte_size(packet.data)} bytes")
      end)

      # Stream packets lazily (memory efficient for large files)
      PcapFileEx.stream("capture.pcap")
      |> Stream.filter(fn packet -> byte_size(packet.data) > 1000 end)
      |> Stream.map(fn packet -> {packet.timestamp, byte_size(packet.data)} end)
      |> Enum.take(10)
  """

  alias PcapFileEx.{Pcap, PcapNg, Stream}

  # Magic numbers for file format detection
  @pcap_magic_le <<0xD4, 0xC3, 0xB2, 0xA1>>
  @pcap_magic_be <<0xA1, 0xB2, 0xC3, 0xD4>>
  @pcapng_magic <<0x0A, 0x0D, 0x0D, 0x0A>>

  @doc """
  Opens a PCAP or PCAPNG file for reading with automatic format detection.

  This function reads the file's magic number to determine whether it's a PCAP
  or PCAPNG file and opens it with the appropriate reader.

  ## Examples

      {:ok, reader} = PcapFileEx.open("capture.pcap")
      {:ok, reader} = PcapFileEx.open("capture.pcapng")

  ## Returns

  - `{:ok, reader}` - A reader struct (either `Pcap.t()` or `PcapNg.t()`)
  - `{:error, reason}` - If the file cannot be opened or has an unknown format
  """
  @spec open(Path.t()) :: {:ok, Pcap.t() | PcapNg.t()} | {:error, String.t()}
  def open(path) when is_binary(path) do
    case detect_format(path) do
      :pcap -> Pcap.open(path)
      :pcapng -> PcapNg.open(path)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Reads all packets from a PCAP or PCAPNG file with automatic format detection.

  Warning: This loads all packets into memory. For large files, use `stream/1` instead.

  ## Examples

      {:ok, packets} = PcapFileEx.read_all("capture.pcap")
      {:ok, packets} = PcapFileEx.read_all("capture.pcapng")
  """
  @spec read_all(Path.t()) :: {:ok, [PcapFileEx.Packet.t()]} | {:error, String.t()}
  def read_all(path) when is_binary(path) do
    case detect_format(path) do
      :pcap -> Pcap.read_all(path)
      :pcapng -> PcapNg.read_all(path)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Creates a lazy stream of packets from a PCAP or PCAPNG file with automatic format detection.

  This is memory efficient for large files as packets are read on demand.
  The file is automatically opened and closed.

  ## Examples

      PcapFileEx.stream("capture.pcap")
      |> Stream.filter(fn packet -> byte_size(packet.data) > 100 end)
      |> Enum.count()

      PcapFileEx.stream("capture.pcapng")
      |> Stream.take(10)
      |> Enum.to_list()
  """
  @spec stream(Path.t()) :: Enumerable.t()
  def stream(path) when is_binary(path) do
    case detect_format(path) do
      :pcap -> Stream.packets(path)
      :pcapng -> stream_pcapng(path)
      {:error, reason} -> raise "Failed to detect file format: #{reason}"
    end
  end

  # Private functions

  @spec detect_format(Path.t()) :: :pcap | :pcapng | {:error, String.t()}
  defp detect_format(path) do
    case File.open(path, [:read, :binary]) do
      {:ok, file} ->
        result =
          case IO.binread(file, 4) do
            @pcap_magic_le -> :pcap
            @pcap_magic_be -> :pcap
            @pcapng_magic -> :pcapng
            magic when is_binary(magic) -> {:error, "Unknown file format (magic: #{inspect(magic)})"}
            :eof -> {:error, "File is empty"}
          end

        File.close(file)
        result

      {:error, reason} ->
        {:error, "Cannot open file: #{:file.format_error(reason)}"}
    end
  end

  defp stream_pcapng(path) do
    Elixir.Stream.resource(
      fn ->
        case PcapNg.open(path) do
          {:ok, reader} -> reader
          {:error, reason} -> raise "Failed to open PCAPNG file: #{reason}"
        end
      end,
      fn reader ->
        case PcapNg.next_packet(reader) do
          {:ok, packet} -> {[packet], reader}
          :eof -> {:halt, reader}
          {:error, reason} -> raise "Error reading packet: #{reason}"
        end
      end,
      fn reader -> PcapNg.close(reader) end
    )
  end
end
