defmodule PcapFileEx do
  @moduledoc """
  Elixir wrapper for parsing PCAP and PCAPNG network capture files.

  This library provides functionality to read packet capture files commonly used
  with tools like Wireshark, tcpdump, and dumpcap.

  ## Modules

  - `PcapFileEx` - Main API with format auto-detection
  - `PcapFileEx.Pcap` - PCAP format reader
  - `PcapFileEx.PcapNg` - PCAPNG format reader
  - `PcapFileEx.Stats` - Statistics and analysis
  - `PcapFileEx.Filter` - Packet filtering helpers
  - `PcapFileEx.Validator` - File validation

  ## Examples

      # Open and read a PCAP file (format auto-detected)
      {:ok, reader} = PcapFileEx.open("capture.pcap")

      # Read all packets at once
      {:ok, packets} = PcapFileEx.read_all("capture.pcap")

      # Stream packets lazily (memory efficient for large files)
      PcapFileEx.stream("capture.pcap")
      |> Stream.filter(fn packet -> byte_size(packet.data) > 1000 end)
      |> Enum.take(10)

      # Compute statistics
      {:ok, stats} = PcapFileEx.Stats.compute("capture.pcap")
      IO.inspect(stats.packet_count)

      # Filter packets
      PcapFileEx.stream("capture.pcap")
      |> PcapFileEx.Filter.by_size(100..1500)
      |> PcapFileEx.Filter.larger_than(500)
      |> Enum.to_list()

      # Validate file
      {:ok, :pcap} = PcapFileEx.Validator.validate("capture.pcap")
  """

  alias PcapFileEx.{Format, Packet, Pcap, PcapNg, Stream}

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
    case Format.detect(path) do
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
  @spec read_all(Path.t(), keyword()) :: {:ok, [PcapFileEx.Packet.t()]} | {:error, String.t()}
  def read_all(path, opts \\ []) when is_binary(path) do
    decode? = Keyword.get(opts, :decode, true)

    result =
      case Format.detect(path) do
        :pcap -> Pcap.read_all(path)
        :pcapng -> PcapNg.read_all(path)
        {:error, reason} -> {:error, reason}
      end

    with {:ok, packets} <- result do
      packets = maybe_attach_decoded(packets, decode?)
      {:ok, packets}
    end
  end

  @doc """
  Creates a lazy stream of packets from a PCAP or PCAPNG file with automatic format detection.

  This is memory efficient for large files as packets are read on demand.
  The file is automatically opened and closed.

  Returns `{:ok, stream}` on success or `{:error, reason}` if the file format
  cannot be detected or the file cannot be opened.

  ## Options

    * `:decode` - If true (default), attaches decoded protocol information to each packet

  ## Examples

      {:ok, stream} = PcapFileEx.stream("capture.pcap")
      stream
      |> Stream.filter(fn packet -> byte_size(packet.data) > 100 end)
      |> Enum.count()

      # Handle errors
      case PcapFileEx.stream("capture.pcapng") do
        {:ok, stream} -> stream |> Enum.take(10)
        {:error, msg} -> IO.puts("Error: \#{msg}")
      end

  ## Migration from 0.1.x

  In version 0.1.x, this function raised on errors. Use `stream!/2` for the old behavior:

      # Old (0.1.x)
      stream = PcapFileEx.stream("capture.pcap")

      # New (0.2.0) - option 1: handle errors
      {:ok, stream} = PcapFileEx.stream("capture.pcap")

      # New (0.2.0) - option 2: use bang variant
      stream = PcapFileEx.stream!("capture.pcap")
  """
  @spec stream(Path.t(), keyword()) :: {:ok, Enumerable.t()} | {:error, String.t()}
  def stream(path, opts \\ []) when is_binary(path) do
    decode? = Keyword.get(opts, :decode, true)

    with format when format in [:pcap, :pcapng] <- Format.detect(path),
         {:ok, base_stream} <- get_base_stream(format, path) do
      stream =
        if decode? do
          Elixir.Stream.map(base_stream, fn
            {:ok, packet} -> {:ok, Packet.attach_decoded(packet)}
            {:error, _} = error -> error
          end)
        else
          base_stream
        end

      {:ok, stream}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Creates a lazy stream of packets, raising on errors.

  This is the old behavior from version 0.1.x.

  The returned stream emits bare packets (not tagged tuples) and raises
  on mid-stream errors.

  ## Examples

      PcapFileEx.stream!("capture.pcap")
      |> Stream.filter(fn packet -> byte_size(packet.data) > 100 end)
      |> Enum.count()
  """
  @spec stream!(Path.t(), keyword()) :: Enumerable.t()
  def stream!(path, opts \\ []) when is_binary(path) do
    case stream(path, opts) do
      {:ok, stream} ->
        # Unwrap tagged tuples and raise on errors
        Elixir.Stream.map(stream, fn
          {:ok, packet} ->
            packet

          {:error, %{reason: reason, packet_index: index}} ->
            raise "Failed to read packet #{index}: #{reason}"
        end)

      {:error, reason} ->
        raise "Failed to create stream: #{reason}"
    end
  end

  # Private functions

  defp get_base_stream(:pcap, path) do
    Stream.packets(path)
  end

  defp get_base_stream(:pcapng, path) do
    stream_pcapng(path)
  end

  defp stream_pcapng(path) do
    # Pre-validate by attempting to open
    case PcapNg.open(path) do
      {:ok, reader} ->
        PcapNg.close(reader)

        stream =
          Elixir.Stream.resource(
            fn ->
              case PcapNg.open(path) do
                {:ok, reader} -> {reader, 0}
                {:error, reason} -> raise "Failed to open PCAPNG file: #{reason}"
              end
            end,
            fn
              :halt ->
                {:halt, :halt}

              {reader, index} ->
                case PcapNg.next_packet(reader) do
                  {:ok, packet} -> {[{:ok, packet}], {reader, index + 1}}
                  :eof -> {:halt, {reader, index}}
                  {:error, reason} -> {[{:error, %{reason: reason, packet_index: index}}], :halt}
                end
            end,
            fn
              :halt -> :ok
              {reader, _index} -> PcapNg.close(reader)
            end
          )

        {:ok, stream}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_attach_decoded(packets, true), do: Enum.map(packets, &Packet.attach_decoded/1)
  defp maybe_attach_decoded(packets, false), do: packets
end
