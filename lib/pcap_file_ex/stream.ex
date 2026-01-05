defmodule PcapFileEx.Stream do
  @moduledoc """
  Stream protocol implementation for lazy packet reading.

  ## Safe vs Raising Variants

  This module provides two styles of stream APIs:

  ### Safe variants (do not raise mid-stream)

  - `packets/1` - Returns `{:ok, stream} | {:error, reason}`, emits tagged tuples
  - `from_reader/1` - Returns stream that emits tagged tuples

  These emit `{:ok, packet}` for successful reads and `{:error, metadata}` for
  corrupted packets or read failures. The stream halts after emitting an error tuple.

  ### Raising variants (raise on errors)

  - `packets!/1` - Raises on file open or mid-stream errors
  - `from_reader!/1` - Raises on mid-stream errors

  These provide the simpler API but cannot gracefully handle corrupted files.

  ## Error Handling

  Safe streams emit error tuples with context:

      {:error, %{reason: "parser error message", packet_index: 42}}

  You can handle these in several ways:

      # Stop on first error
      {:ok, stream} = Stream.packets("capture.pcap")
      Enum.reduce_while(stream, [], fn
        {:ok, packet}, acc -> {:cont, [packet | acc]}
        {:error, %{reason: r, packet_index: i}}, _acc ->
          {:halt, {:error, "Packet \#{i} failed: \#{r}"}}
      end)

      # Skip errors and continue
      stream
      |> Stream.filter(fn
        {:ok, _} -> true
        {:error, meta} -> Logger.warning("Skipped: \#{inspect(meta)}"); false
      end)
      |> Stream.map(fn {:ok, packet} -> packet end)

  ## Migration from 0.2.x to 0.3.0

  In v0.2.x, `packets/1` validated at construction but raised mid-stream on errors.
  In v0.3.0, it emits tagged tuples instead:

  - Before: `{:ok, stream} = packets(path); packets = Enum.to_list(stream)`
  - After: Handle tuples or use `packets!/1` for raising behavior
  """

  alias PcapFileEx.{Packet, Pcap, PcapNg}

  @typedoc """
  Error metadata emitted by safe streams when a packet read fails.

  Contains the error reason and the 0-based index of the packet that failed to read.
  """
  @type error_metadata :: %{
          reason: String.t(),
          packet_index: non_neg_integer()
        }

  @typedoc """
  Tagged tuple emitted by safe streams. Either a successful packet read or an error.
  """
  @type stream_item :: {:ok, Packet.t()} | {:error, error_metadata()}

  @doc """
  Creates a lazy stream of packets from a PCAP file.

  Pre-validates that the file can be opened before returning the stream.
  Returns `{:ok, stream}` on success or `{:error, reason}` if the file
  cannot be opened.

  The stream automatically handles opening and closing the file.

  The returned stream emits tagged tuples:
  - `{:ok, packet}` for successful packet reads
  - `{:error, metadata}` for read failures (corrupted data, I/O errors, etc.)

  The stream halts after emitting an error tuple. To continue reading past
  errors or to get raising behavior, use `packets!/1` instead.

  ## Options

  - `:hosts_map` - Map of IP address strings to hostname strings for endpoint resolution

  ## Examples

      # Basic usage with pattern matching
      {:ok, stream} = PcapFileEx.Stream.packets("capture.pcap")

      packets = stream
      |> Stream.map(fn
        {:ok, packet} -> packet
        {:error, meta} -> raise "Error at packet \#{meta.packet_index}: \#{meta.reason}"
      end)
      |> Enum.to_list()

      # Stop on first error
      result = Enum.reduce_while(stream, [], fn
        {:ok, packet}, acc -> {:cont, [packet | acc]}
        {:error, %{packet_index: i, reason: r}}, _acc ->
          {:halt, {:error, "Failed at packet \#{i}: \#{r}"}}
      end)

      # Skip errors and continue
      valid_packets = stream
      |> Stream.filter(fn
        {:ok, _} -> true
        {:error, _} -> false
      end)
      |> Stream.map(fn {:ok, packet} -> packet end)
      |> Enum.to_list()

      # Handle file open errors
      case PcapFileEx.Stream.packets("nonexistent.pcap") do
        {:ok, stream} -> process_stream(stream)
        {:error, msg} -> IO.puts("Cannot open file: \#{msg}")
      end

      # With hosts mapping
      hosts = %{"192.168.1.1" => "gateway", "10.0.0.1" => "server"}
      {:ok, stream} = PcapFileEx.Stream.packets("capture.pcap", hosts_map: hosts)
  """
  @spec packets(Path.t()) :: {:ok, Enumerable.t(stream_item())} | {:error, String.t()}
  def packets(path), do: packets(path, [])

  @spec packets(Path.t(), keyword()) :: {:ok, Enumerable.t(stream_item())} | {:error, String.t()}
  def packets(path, opts) do
    # Pre-validate by attempting to open
    case Pcap.open(path) do
      {:ok, reader} ->
        Pcap.close(reader)

        stream =
          Stream.resource(
            # Start function: open the file with packet counter
            fn ->
              case Pcap.open(path) do
                {:ok, reader} -> {reader, 0}
                {:error, reason} -> raise "Failed to open PCAP file: #{reason}"
              end
            end,
            # Next function: read packets and emit tagged tuples
            fn
              :halt ->
                {:halt, :halt}

              {reader, index} ->
                case Pcap.next_packet(reader, opts) do
                  {:ok, packet} -> {[{:ok, packet}], {reader, index + 1}}
                  :eof -> {:halt, {reader, index}}
                  {:error, reason} -> {[{:error, %{reason: reason, packet_index: index}}], :halt}
                end
            end,
            # End function: close the file
            fn
              :halt -> :ok
              {reader, _index} -> Pcap.close(reader)
            end
          )

        {:ok, stream}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Creates a lazy stream of packets from a PCAP file, raising on errors.

  This is the old behavior from version 0.1.x.

  ## Options

  - `:hosts_map` - Map of IP address strings to hostname strings for endpoint resolution

  ## Examples

      PcapFileEx.Stream.packets!("capture.pcap")
      |> Stream.filter(fn packet -> byte_size(packet.data) > 1000 end)
      |> Enum.take(10)

      # With hosts mapping
      hosts = %{"192.168.1.1" => "gateway"}
      PcapFileEx.Stream.packets!("capture.pcap", hosts_map: hosts)
      |> Enum.take(10)
  """
  @spec packets!(Path.t()) :: Enumerable.t()
  def packets!(path), do: packets!(path, [])

  @spec packets!(Path.t(), keyword()) :: Enumerable.t()
  def packets!(path, opts) do
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
        case Pcap.next_packet(reader, opts) do
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

  The returned stream emits tagged tuples:
  - `{:ok, packet}` for successful packet reads
  - `{:error, metadata}` for read failures (corrupted data, I/O errors, etc.)

  The stream halts after emitting an error tuple. For raising behavior,
  use `from_reader!/1` instead.

  ## Options

  - `:hosts_map` - Map of IP address strings to hostname strings for endpoint resolution

  ## Examples

      {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
      stream = PcapFileEx.Stream.from_reader(reader)

      valid_packets = stream
      |> Stream.filter(fn
        {:ok, _} -> true
        {:error, _} -> false
      end)
      |> Stream.map(fn {:ok, packet} -> packet end)
      |> Enum.take(10)

      PcapFileEx.Pcap.close(reader)

      # PCAPNG example
      {:ok, reader} = PcapFileEx.PcapNg.open("capture.pcapng")
      stream = PcapFileEx.Stream.from_reader(reader)
      # ... process stream ...
      PcapFileEx.PcapNg.close(reader)

      # With hosts mapping
      hosts = %{"192.168.1.1" => "gateway"}
      stream = PcapFileEx.Stream.from_reader(reader, hosts_map: hosts)
  """
  @spec from_reader(Pcap.t() | PcapNg.t()) :: Enumerable.t(stream_item())
  def from_reader(reader), do: from_reader(reader, [])

  @spec from_reader(Pcap.t() | PcapNg.t(), keyword()) :: Enumerable.t(stream_item())
  def from_reader(%Pcap{} = reader, opts) do
    Stream.resource(
      fn -> {reader, 0} end,
      fn
        :halt ->
          {:halt, :halt}

        {reader, index} ->
          case Pcap.next_packet(reader, opts) do
            {:ok, packet} -> {[{:ok, packet}], {reader, index + 1}}
            :eof -> {:halt, {reader, index}}
            {:error, reason} -> {[{:error, %{reason: reason, packet_index: index}}], :halt}
          end
      end,
      fn
        :halt -> :ok
        {_reader, _index} -> :ok
      end
    )
  end

  def from_reader(%PcapNg{} = reader, opts) do
    Stream.resource(
      fn -> {reader, 0} end,
      fn
        :halt ->
          {:halt, :halt}

        {reader, index} ->
          case PcapNg.next_packet(reader, opts) do
            {:ok, packet} -> {[{:ok, packet}], {reader, index + 1}}
            :eof -> {:halt, {reader, index}}
            {:error, reason} -> {[{:error, %{reason: reason, packet_index: index}}], :halt}
          end
      end,
      fn
        :halt -> :ok
        {_reader, _index} -> :ok
      end
    )
  end

  @doc """
  Creates a lazy stream of packets from an already opened reader, raising on errors.

  This does NOT automatically close the reader when done.
  Works with both PCAP and PCAPNG readers.

  ## Options

  - `:hosts_map` - Map of IP address strings to hostname strings for endpoint resolution

  ## Examples

      {:ok, reader} = PcapFileEx.Pcap.open("capture.pcap")
      PcapFileEx.Stream.from_reader!(reader)
      |> Enum.take(10)
      PcapFileEx.Pcap.close(reader)

      # With hosts mapping
      hosts = %{"192.168.1.1" => "gateway"}
      PcapFileEx.Stream.from_reader!(reader, hosts_map: hosts)
      |> Enum.take(10)
  """
  @spec from_reader!(Pcap.t() | PcapNg.t()) :: Enumerable.t()
  def from_reader!(reader), do: from_reader!(reader, [])

  @spec from_reader!(Pcap.t() | PcapNg.t(), keyword()) :: Enumerable.t()
  def from_reader!(%Pcap{} = reader, opts) do
    Stream.resource(
      fn -> reader end,
      fn reader ->
        case Pcap.next_packet(reader, opts) do
          {:ok, packet} -> {[packet], reader}
          :eof -> {:halt, reader}
          {:error, reason} -> raise "Failed to read packet: #{reason}"
        end
      end,
      fn _reader -> :ok end
    )
  end

  def from_reader!(%PcapNg{} = reader, opts) do
    Stream.resource(
      fn -> reader end,
      fn reader ->
        case PcapNg.next_packet(reader, opts) do
          {:ok, packet} -> {[packet], reader}
          :eof -> {:halt, reader}
          {:error, reason} -> raise "Failed to read packet: #{reason}"
        end
      end,
      fn _reader -> :ok end
    )
  end
end
