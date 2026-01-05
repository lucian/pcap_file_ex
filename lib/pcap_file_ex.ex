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

  alias PcapFileEx.{Format, Packet, Pcap, PcapNg}
  alias PcapFileEx.Stream, as: PcapStream

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

  ## Options

    * `:decode` - If true (default), attaches decoded protocol information to each packet
    * `:hosts_map` - Map of IP address strings to hostname strings for endpoint resolution

  ## Examples

      {:ok, packets} = PcapFileEx.read_all("capture.pcap")
      {:ok, packets} = PcapFileEx.read_all("capture.pcapng")

      # With hosts mapping
      hosts = %{"192.168.1.1" => "gateway", "10.0.0.1" => "server"}
      {:ok, packets} = PcapFileEx.read_all("capture.pcap", hosts_map: hosts)
  """
  @spec read_all(Path.t(), keyword()) :: {:ok, [PcapFileEx.Packet.t()]} | {:error, String.t()}
  def read_all(path, opts \\ []) when is_binary(path) do
    decode? = Keyword.get(opts, :decode, true)

    result =
      case Format.detect(path) do
        :pcap -> Pcap.read_all(path, opts)
        :pcapng -> PcapNg.read_all(path, opts)
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
    * `:hosts_map` - Map of IP address strings to hostname strings for endpoint resolution

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

      # With hosts mapping
      hosts = %{"192.168.1.1" => "gateway", "10.0.0.1" => "server"}
      {:ok, stream} = PcapFileEx.stream("capture.pcap", hosts_map: hosts)

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
         {:ok, base_stream} <- get_base_stream(format, path, opts) do
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

  defp get_base_stream(:pcap, path, opts) do
    PcapStream.packets(path, opts)
  end

  defp get_base_stream(:pcapng, path, opts) do
    stream_pcapng(path, opts)
  end

  defp stream_pcapng(path, opts) do
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
                case PcapNg.next_packet(reader, opts) do
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

  @doc """
  Writes packets to a PCAP or PCAPNG file.

  Format is determined by file extension (.pcap or .pcapng).

  ## Parameters

    * `path` - Output file path
    * `header` - PCAP header (for .pcap files)
    * `packets` - Enumerable of packets

  ## Options

    * `:format` - Override format detection (:pcap or :pcapng)
    * `:interfaces` - Required for PCAPNG format (list of Interface structs)
    * `:endianness` - For PCAPNG files ("big" or "little", default: "little")

  ## Returns

    * `{:ok, count}` - Number of packets written
    * `{:error, reason}` - Write failed

  ## Examples

      # Write PCAP file
      header = %PcapFileEx.Header{...}
      {:ok, 100} = PcapFileEx.write("output.pcap", header, packets)

      # Write PCAPNG file
      interfaces = [%PcapFileEx.Interface{...}]
      {:ok, 100} = PcapFileEx.write("output.pcapng", nil, packets, interfaces: interfaces)
  """
  @spec write(Path.t(), PcapFileEx.Header.t() | nil, Enumerable.t(), keyword()) ::
          {:ok, non_neg_integer()} | {:error, String.t()}
  def write(path, header_or_nil, packets, opts \\ []) when is_binary(path) do
    format = Keyword.get(opts, :format, detect_format_from_extension(path))

    case format do
      :pcap when is_nil(header_or_nil) ->
        {:error, "PCAP format requires header parameter"}

      :pcap ->
        PcapFileEx.PcapWriter.write_all(path, header_or_nil, packets)

      :pcapng ->
        interfaces = Keyword.get(opts, :interfaces)

        if is_nil(interfaces) or interfaces == [] do
          {:error,
           "PCAPNG format requires :interfaces option. " <>
             "Extract from source using PcapFileEx.PcapNg.interfaces/1"}
        else
          endianness_opt = Keyword.take(opts, [:endianness])
          PcapFileEx.PcapNgWriter.write_all(path, interfaces, packets, endianness_opt)
        end

      _ ->
        {:error, "Unknown format. Use .pcap or .pcapng extension, or specify :format option"}
    end
  end

  @doc """
  Writes packets to a file, raising on error.

  See `write/4` for details.
  """
  @spec write!(Path.t(), PcapFileEx.Header.t() | nil, Enumerable.t(), keyword()) ::
          non_neg_integer()
  def write!(path, header_or_nil, packets, opts \\ []) do
    case write(path, header_or_nil, packets, opts) do
      {:ok, count} -> count
      {:error, reason} -> raise "Failed to write PCAP file: #{reason}"
    end
  end

  @doc """
  Copies a PCAP/PCAPNG file to a new location, optionally converting format.

  ## Parameters

    * `source_path` - Input file path
    * `dest_path` - Output file path

  ## Options

    * `:format` - Output format (:pcap or :pcapng, default: auto-detect from extension)
    * `:on_error` - How to handle read errors (:halt or :skip, default: :halt)

  ## Returns

    * `{:ok, count}` - Number of packets copied
    * `{:error, reason}` - Copy failed

  ## Examples

      # Simple copy
      {:ok, 1000} = PcapFileEx.copy("input.pcap", "output.pcap")

      # Convert PCAP to PCAPNG
      {:ok, 1000} = PcapFileEx.copy("input.pcap", "output.pcapng")

      # Skip corrupt packets
      {:ok, 995} = PcapFileEx.copy("input.pcap", "output.pcap", on_error: :skip)
  """
  @spec copy(Path.t(), Path.t(), keyword()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def copy(source_path, dest_path, opts \\ [])
      when is_binary(source_path) and is_binary(dest_path) do
    output_format = Keyword.get(opts, :format, detect_format_from_extension(dest_path))
    on_error = Keyword.get(opts, :on_error, :halt)

    try do
      with {:ok, source_format} <- detect_format_with_validation(source_path),
           {:ok, header} <- get_header(source_path),
           {:ok, source_stream} <- stream(source_path) do
        # Handle both success and error tuples from safe stream
        packets_stream =
          source_stream
          |> Elixir.Stream.flat_map(fn
            {:ok, packet} ->
              [packet]

            {:error, meta} ->
              case on_error do
                :halt ->
                  throw(
                    {:copy_error, "Read failed at packet #{meta.packet_index}: #{meta.reason}"}
                  )

                :skip ->
                  require Logger

                  Logger.warning(
                    "Skipping corrupt packet #{meta.packet_index} during copy: #{meta.reason}"
                  )

                  []
              end
          end)

        # Write with appropriate format
        case output_format do
          :pcap ->
            write(dest_path, header, packets_stream, format: :pcap)

          :pcapng ->
            # Extract or create interfaces
            interfaces =
              case source_format do
                :pcapng ->
                  # Extract interfaces from source
                  case extract_interfaces_from_reader(source_path) do
                    {:ok, ifaces} -> ifaces
                    {:error, _} -> [create_default_interface_from_header(header)]
                  end

                :pcap ->
                  # Source is PCAP - create default interface from header
                  [create_default_interface_from_header(header)]
              end

            # Assign interface_id for PCAPNG format (PCAP packets don't have interface_id)
            packets_with_interface =
              if source_format == :pcap do
                packets_stream |> Elixir.Stream.map(&%{&1 | interface_id: 0})
              else
                packets_stream
              end

            write(dest_path, nil, packets_with_interface, format: :pcapng, interfaces: interfaces)
        end
      end
    catch
      {:copy_error, reason} -> {:error, reason}
    end
  end

  @doc """
  Exports filtered packets to a new file.

  Convenience function that combines filtering and writing.

  ## Parameters

    * `source_path` - Input file path
    * `dest_path` - Output file path
    * `filter_fun` - Function to filter packets (packet -> boolean)

  ## Options

    * `:format` - Output format (:pcap or :pcapng, default: auto-detect)
    * `:on_error` - How to handle read errors (:halt or :skip, default: :halt)

  ## Returns

    * `{:ok, count}` - Number of packets exported
    * `{:error, reason}` - Export failed

  ## Examples

      # Export only large packets
      filter = fn packet -> byte_size(packet.data) > 1000 end
      {:ok, 50} = PcapFileEx.export_filtered("input.pcap", "large.pcap", filter)

      # Export HTTP traffic
      filter = fn packet -> packet.protocol == :http end
      {:ok, 100} = PcapFileEx.export_filtered("input.pcap", "http.pcap", filter)
  """
  @spec export_filtered(Path.t(), Path.t(), (Packet.t() -> boolean()), keyword()) ::
          {:ok, non_neg_integer()} | {:error, String.t()}
  def export_filtered(source_path, dest_path, filter_fun, opts \\ [])
      when is_binary(source_path) and is_binary(dest_path) and is_function(filter_fun, 1) do
    output_format = Keyword.get(opts, :format, detect_format_from_extension(dest_path))
    on_error = Keyword.get(opts, :on_error, :halt)

    try do
      with {:ok, source_format} <- detect_format_with_validation(source_path),
           {:ok, header} <- get_header(source_path),
           {:ok, source_stream} <- stream(source_path) do
        # Filter packets and handle errors
        packets_only =
          source_stream
          |> Elixir.Stream.flat_map(fn
            {:ok, packet} ->
              if filter_fun.(packet), do: [packet], else: []

            {:error, meta} ->
              case on_error do
                :halt ->
                  throw(
                    {:export_error, "Read failed at packet #{meta.packet_index}: #{meta.reason}"}
                  )

                :skip ->
                  require Logger

                  Logger.warning(
                    "Skipping corrupt packet #{meta.packet_index} during export: #{meta.reason}"
                  )

                  []
              end
          end)

        # Write with appropriate format
        case output_format do
          :pcap ->
            write(dest_path, header, packets_only, format: :pcap)

          :pcapng ->
            # Extract or create interfaces
            interfaces =
              case source_format do
                :pcapng ->
                  case extract_interfaces_from_reader(source_path) do
                    {:ok, ifaces} -> ifaces
                    {:error, _} -> [create_default_interface_from_header(header)]
                  end

                :pcap ->
                  [create_default_interface_from_header(header)]
              end

            # Assign interface_id for PCAPNG format (PCAP packets don't have interface_id)
            packets_with_interface =
              if source_format == :pcap do
                packets_only |> Elixir.Stream.map(&%{&1 | interface_id: 0})
              else
                packets_only
              end

            write(dest_path, nil, packets_with_interface, format: :pcapng, interfaces: interfaces)
        end
      end
    catch
      {:export_error, reason} -> {:error, reason}
    end
  end

  @doc """
  Exports filtered packets to a new file, raising on error.

  See `export_filtered/4` for details.
  """
  @spec export_filtered!(Path.t(), Path.t(), (Packet.t() -> boolean()), keyword()) ::
          non_neg_integer()
  def export_filtered!(source_path, dest_path, filter_fun, opts \\ []) do
    case export_filtered(source_path, dest_path, filter_fun, opts) do
      {:ok, count} -> count
      {:error, reason} -> raise "Failed to export filtered packets: #{reason}"
    end
  end

  # Private helper: Detect format from file extension
  defp detect_format_from_extension(path) do
    cond do
      String.ends_with?(path, ".pcapng") -> :pcapng
      String.ends_with?(path, ".pcap") -> :pcap
      # Default to PCAP
      true -> :pcap
    end
  end

  # Private helper: Detect format with proper error handling
  # Converts Format.detect/1's :pcap | :pcapng | {:error, ...} to tagged tuple
  defp detect_format_with_validation(path) do
    case Format.detect(path) do
      :pcap -> {:ok, :pcap}
      :pcapng -> {:ok, :pcapng}
      {:error, reason} -> {:error, reason}
    end
  end

  # Private helper: Get header from any format file
  defp get_header(path) do
    case Format.detect(path) do
      :pcap ->
        with {:ok, reader} <- Pcap.open(path) do
          try do
            {:ok, reader.header}
          after
            Pcap.close(reader)
          end
        end

      :pcapng ->
        with {:ok, reader} <- PcapNg.open(path) do
          try do
            # PCAPNG doesn't have a global header, create a default PCAP header
            # based on the first interface
            with {:ok, interfaces} <- PcapNg.interfaces(reader) do
              header =
                case List.first(interfaces) do
                  nil ->
                    # No interfaces, use defaults
                    %PcapFileEx.Header{
                      version_major: 2,
                      version_minor: 4,
                      snaplen: 65_535,
                      datalink: "ethernet",
                      ts_resolution: "microsecond",
                      endianness: "little"
                    }

                  first ->
                    %PcapFileEx.Header{
                      version_major: 2,
                      version_minor: 4,
                      snaplen: first.snaplen,
                      datalink: first.linktype,
                      ts_resolution:
                        case first.timestamp_resolution do
                          :nanosecond -> "nanosecond"
                          :microsecond -> "microsecond"
                          _ -> "microsecond"
                        end,
                      endianness: "little"
                    }
                end

              {:ok, header}
            end
          after
            PcapNg.close(reader)
          end
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private helper: Extract interfaces from PCAPNG reader
  defp extract_interfaces_from_reader(path) do
    with {:ok, reader} <- PcapNg.open(path) do
      try do
        PcapNg.interfaces(reader)
      after
        PcapNg.close(reader)
      end
    end
  end

  # Private helper: Create default interface for PCAP->PCAPNG conversion
  # Derives interface fields from source PCAP header to preserve datalink and snaplen
  defp create_default_interface_from_header(%PcapFileEx.Header{} = header) do
    %PcapFileEx.Interface{
      id: 0,
      linktype: header.datalink,
      snaplen: header.snaplen,
      name: "pcap0",
      description: "Converted from PCAP (#{header.datalink}, snaplen=#{header.snaplen})",
      timestamp_resolution:
        case header.ts_resolution do
          "nanosecond" -> :nanosecond
          "microsecond" -> :microsecond
          _ -> :microsecond
        end,
      timestamp_resolution_raw: header.ts_resolution,
      timestamp_offset_secs: 0
    }
  end

  defp maybe_attach_decoded(packets, true), do: Enum.map(packets, &Packet.attach_decoded/1)
  defp maybe_attach_decoded(packets, false), do: packets
end
