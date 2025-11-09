defmodule PcapFileEx.Stream do
  @moduledoc """
  Stream protocol implementation for lazy packet reading.

  ## Migration from 0.1.x to 0.2.0

  The stream API has changed to follow Elixir conventions:

  - `packets/1` now returns `{:ok, stream} | {:error, reason}` (safe)
  - `packets!/1` raises on errors (old behavior)
  - `from_reader/1` now returns `{:ok, stream} | {:error, reason}` for validation
  - `from_reader!/1` raises on errors (old behavior)

  To migrate existing code, either:
  1. Add `!` to your stream calls: `Stream.packets!(path)`
  2. Handle the new return type: `{:ok, stream} = Stream.packets(path)`
  """

  alias PcapFileEx.{Pcap, PcapNg}

  @doc """
  Creates a lazy stream of packets from a PCAP file.

  Pre-validates that the file can be opened before returning the stream.
  Returns `{:ok, stream}` on success or `{:error, reason}` if the file
  cannot be opened.

  The stream automatically handles opening and closing the file.

  ## Examples

      {:ok, stream} = PcapFileEx.Stream.packets("capture.pcap")
      stream
      |> Stream.filter(fn packet -> byte_size(packet.data) > 1000 end)
      |> Enum.take(10)

      # Handle errors
      case PcapFileEx.Stream.packets("nonexistent.pcap") do
        {:ok, stream} -> Enum.to_list(stream)
        {:error, msg} -> IO.puts("Error: \#{msg}")
      end
  """
  @spec packets(Path.t()) :: {:ok, Enumerable.t()} | {:error, String.t()}
  def packets(path) do
    # Pre-validate by attempting to open
    case Pcap.open(path) do
      {:ok, reader} ->
        Pcap.close(reader)
        {:ok, packets!(path)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Creates a lazy stream of packets from a PCAP file, raising on errors.

  This is the old behavior from version 0.1.x.

  ## Examples

      PcapFileEx.Stream.packets!("capture.pcap")
      |> Stream.filter(fn packet -> byte_size(packet.data) > 1000 end)
      |> Enum.take(10)
  """
  @spec packets!(Path.t()) :: Enumerable.t()
  def packets!(path) do
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
  Works with both PCAP and PCAPNG readers.

  Returns `{:ok, stream}`. Unlike `packets/1`, this cannot fail since
  the reader is already validated and opened.

  ## Examples

      {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
      {:ok, stream} = PcapFileEx.Stream.from_reader(reader)
      stream |> Enum.take(10)
      PcapFileEx.Pcap.close(reader)

      {:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")
      {:ok, stream} = PcapFileEx.Stream.from_reader(reader)
      stream |> Enum.take(10)
      PcapFileEx.PcapNg.close(reader)
  """
  @spec from_reader(Pcap.t() | PcapNg.t()) :: {:ok, Enumerable.t()}
  def from_reader(reader) do
    {:ok, from_reader!(reader)}
  end

  @doc """
  Creates a lazy stream of packets from an already opened reader, raising on errors.

  This does NOT automatically close the reader when done.
  Works with both PCAP and PCAPNG readers.

  ## Examples

      {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
      PcapFileEx.Stream.from_reader!(reader)
      |> Enum.take(10)
      PcapFileEx.Pcap.close(reader)
  """
  @spec from_reader!(Pcap.t() | PcapNg.t()) :: Enumerable.t()
  def from_reader!(%Pcap{} = reader) do
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

  def from_reader!(%PcapNg{} = reader) do
    Stream.resource(
      fn -> reader end,
      fn reader ->
        case PcapNg.next_packet(reader) do
          {:ok, packet} -> {[packet], reader}
          :eof -> {:halt, reader}
          {:error, reason} -> raise "Failed to read packet: #{reason}"
        end
      end,
      fn _reader -> :ok end
    )
  end
end
