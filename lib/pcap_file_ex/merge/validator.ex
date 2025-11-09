defmodule PcapFileEx.Merge.Validator do
  @moduledoc """
  Validation for multi-file merge operations.

  This module provides datalink compatibility validation and clock synchronization
  validation for merging multiple PCAP/PCAPNG files.
  """

  alias PcapFileEx.{Format, Pcap, PcapNg, Timestamp}
  alias PcapFileEx.Merge.ValidationCache

  @max_acceptable_drift_ms 1000.0

  @doc """
  Validates that all files have compatible datalink types.

  ## PCAP Validation
  - All files must have identical global datalink types

  ## PCAPNG Validation
  - Extracts all Interface Description Blocks (IDBs) from each file
  - Determines which interfaces are ACTIVE (packet_count > 0)
  - ALL active interfaces across ALL files must share at least one common datalink type
  - Declared-but-unused interfaces (packet_count = 0) are ignored

  ## Returns

  - `{:ok, validation_result}` - Validation succeeded
  - `{:error, {:no_common_datalink, details}}` - Incompatible datalink types

  ## Examples

      {:ok, _} = PcapFileEx.Merge.Validator.validate_datalinks(["s1.pcap", "s2.pcap"])

      # PCAPNG with active interface validation
      {:ok, result} = PcapFileEx.Merge.Validator.validate_datalinks([
        "server1.pcapng",  # Has ethernet:1000pkts, wifi:0pkts
        "server2.pcapng"   # Has ethernet:1000pkts
      ])
      # Passes: wifi interface is unused (0 packets), only ethernet validated
  """
  @spec validate_datalinks([String.t()]) ::
          {:ok, map()} | {:error, {:no_common_datalink, map()}}
  def validate_datalinks(paths) when is_list(paths) do
    files_info =
      paths
      |> Enum.map(&get_file_datalink_info/1)

    # Check if all files are PCAP (simple case)
    if Enum.all?(files_info, &(&1.format == :pcap)) do
      validate_pcap_datalinks(files_info)
    else
      # At least one PCAPNG file, need full active interface validation
      validate_pcapng_datalinks(files_info)
    end
  end

  @doc """
  Validates clock synchronization across multiple capture files.

  Performs a full scan of all files to collect timing statistics and detect
  potential clock drift between systems.

  **Performance Note**: This performs a full scan and is NOT included in the
  merge overhead target. Results are cached by (file_path, mtime, size).

  ## Parameters

  - `paths` - List of file paths to validate

  ## Returns

  - `{:ok, stats}` - Validation succeeded
  - `{:error, {:excessive_drift, meta}}` - Clock drift exceeds threshold (1000ms)

  ## Examples

      case PcapFileEx.Merge.Validator.validate_clocks(["s1.pcap", "s2.pcap"]) do
        {:ok, stats} -> IO.inspect(stats.max_drift_ms)
        {:error, {:excessive_drift, meta}} -> IO.puts("Drift: \#{meta.max_drift_ms}ms")
      end
  """
  @spec validate_clocks([String.t()]) ::
          {:ok, map()} | {:error, {:excessive_drift, map()}}
  def validate_clocks(paths) when is_list(paths) do
    timing_stats =
      paths
      |> Enum.map(&get_file_timing_stats/1)
      |> Enum.filter(&(&1 != nil))

    if Enum.empty?(timing_stats) do
      {:ok, %{max_drift_ms: 0.0, files: []}}
    else
      max_drift_ms = calculate_max_drift(timing_stats)

      stats = %{
        max_drift_ms: max_drift_ms,
        files: timing_stats
      }

      if max_drift_ms > @max_acceptable_drift_ms do
        {:error, {:excessive_drift, stats}}
      else
        {:ok, stats}
      end
    end
  end

  # Private functions

  defp get_file_datalink_info(path) do
    format = Format.detect(path)

    case format do
      :pcap ->
        {:ok, reader} = Pcap.open(path)
        datalink = reader.header.datalink
        Pcap.close(reader)

        %{
          path: path,
          format: :pcap,
          datalink: datalink,
          active_interfaces: nil
        }

      :pcapng ->
        # Scan file to determine active interfaces
        {:ok, reader} = PcapNg.open(path)

        # Build map of interface_id => packet_count
        interface_counts =
          count_packets_per_interface(reader)

        # Get interface metadata
        {:ok, interfaces} = PcapNg.interfaces(reader)
        PcapNg.close(reader)

        # Build active interface list (packet_count > 0)
        active_interfaces =
          interfaces
          |> Enum.map(fn iface ->
            packet_count = Map.get(interface_counts, iface.id, 0)

            %{
              id: iface.id,
              datalink: iface.linktype,
              packet_count: packet_count
            }
          end)
          |> Enum.filter(&(&1.packet_count > 0))

        %{
          path: path,
          format: :pcapng,
          datalink: nil,
          active_interfaces: active_interfaces
        }

      _ ->
        %{path: path, format: :unknown, datalink: nil, active_interfaces: nil}
    end
  end

  defp count_packets_per_interface(reader) do
    count_packets_loop(reader, %{})
  end

  defp count_packets_loop(reader, counts) do
    case PcapNg.next_packet(reader) do
      {:ok, packet} ->
        interface_id = packet.interface_id || 0
        new_counts = Map.update(counts, interface_id, 1, &(&1 + 1))
        count_packets_loop(reader, new_counts)

      :eof ->
        counts

      {:error, _} ->
        counts
    end
  end

  defp validate_pcap_datalinks(files_info) do
    datalinks = Enum.map(files_info, & &1.datalink) |> Enum.uniq()

    if length(datalinks) == 1 do
      {:ok, %{common_datalink: hd(datalinks), format: :pcap}}
    else
      details = %{
        files:
          Enum.map(files_info, fn info ->
            %{path: info.path, datalink: info.datalink}
          end),
        common_datalinks: [],
        incompatible_files: files_info,
        details: "PCAP files have different datalink types: #{inspect(datalinks)}"
      }

      {:error, {:no_common_datalink, details}}
    end
  end

  defp validate_pcapng_datalinks(files_info) do
    # Collect all active datalinks across all files
    all_active_datalinks =
      files_info
      |> Enum.flat_map(fn file ->
        case file.format do
          :pcap ->
            # PCAP file in a mixed set: treat as single active interface
            [file.datalink]

          :pcapng ->
            # Extract datalinks from active interfaces
            file.active_interfaces
            |> Enum.map(& &1.datalink)

          _ ->
            []
        end
      end)
      |> Enum.uniq()

    # Find common datalinks (present in ALL files' active interfaces)
    common_datalinks = find_common_datalinks(files_info)

    if Enum.empty?(common_datalinks) do
      # Build detailed error message
      incompatible_interfaces =
        files_info
        |> Enum.flat_map(fn file ->
          case file.format do
            :pcapng ->
              file.active_interfaces
              |> Enum.map(fn iface ->
                %{
                  file: file.path,
                  interface_id: iface.id,
                  datalink: iface.datalink,
                  packet_count: iface.packet_count
                }
              end)

            :pcap ->
              [
                %{
                  file: file.path,
                  interface_id: 0,
                  datalink: file.datalink,
                  packet_count: :all
                }
              ]

            _ ->
              []
          end
        end)

      details = %{
        files:
          Enum.map(files_info, fn info ->
            case info.format do
              :pcap ->
                %{path: info.path, datalink: info.datalink, active_interfaces: nil}

              :pcapng ->
                %{path: info.path, datalink: nil, active_interfaces: info.active_interfaces}

              _ ->
                %{path: info.path, datalink: nil, active_interfaces: nil}
            end
          end),
        common_datalinks: [],
        incompatible_interfaces: incompatible_interfaces,
        details: build_incompatible_message(all_active_datalinks, incompatible_interfaces)
      }

      {:error, {:no_common_datalink, details}}
    else
      {:ok,
       %{
         common_datalinks: common_datalinks,
         format: :mixed
       }}
    end
  end

  defp find_common_datalinks(files_info) do
    # Get set of active datalinks for each file
    file_datalink_sets =
      files_info
      |> Enum.map(fn file ->
        case file.format do
          :pcap ->
            MapSet.new([file.datalink])

          :pcapng ->
            file.active_interfaces
            |> Enum.map(& &1.datalink)
            |> MapSet.new()

          _ ->
            MapSet.new()
        end
      end)

    # Find intersection of all sets
    if Enum.empty?(file_datalink_sets) do
      []
    else
      file_datalink_sets
      |> Enum.reduce(fn set, acc -> MapSet.intersection(acc, set) end)
      |> MapSet.to_list()
    end
  end

  defp build_incompatible_message(all_datalinks, incompatible_interfaces) do
    non_common =
      Enum.map_join(incompatible_interfaces, ", ", fn iface ->
        "#{iface.datalink} (#{iface.file}:#{iface.interface_id}, #{iface.packet_count} pkts)"
      end)

    "Not all active interfaces share a common datalink type. " <>
      "Active datalinks: #{inspect(all_datalinks)}. " <>
      "Incompatible interfaces: #{non_common}"
  end

  defp get_file_timing_stats(path) do
    # Try cache first (keyed by path, mtime, size)
    case ValidationCache.get(path) do
      nil ->
        # Cache miss - scan file and cache result
        stats = scan_file_timing_stats(path)

        if stats do
          ValidationCache.put(path, stats)
        end

        stats

      cached_stats ->
        # Cache hit - return cached result
        cached_stats
    end
  end

  defp scan_file_timing_stats(path) do
    # Use streaming to get first and last timestamps without loading entire file
    # Note: Safe streams return {:ok, packet}, {:error, meta}, {:skipped_packet, meta} tuples
    case PcapFileEx.stream(path) do
      {:ok, stream} ->
        # Use reduce_while to stream through file, tracking first/last timestamps
        result =
          Enum.reduce_while(stream, %{first: nil, last: nil, count: 0}, fn
            {:ok, packet}, acc ->
              # Update first timestamp (only once), always update last
              new_acc = %{
                first: acc.first || packet.timestamp_precise,
                last: packet.timestamp_precise,
                count: acc.count + 1
              }

              {:cont, new_acc}

            {:error, _meta}, acc ->
              # Skip errors, continue processing
              {:cont, acc}

            {:skipped_packet, _meta}, acc ->
              # Skip skipped packets, continue processing
              {:cont, acc}

            # Handle any other tuple format gracefully
            _, acc ->
              {:cont, acc}
          end)

        # Return nil if no packets were successfully read
        if result.count == 0 or is_nil(result.first) do
          nil
        else
          duration_ns =
            Timestamp.to_unix_nanos(result.last) - Timestamp.to_unix_nanos(result.first)

          %{
            path: path,
            first_timestamp: result.first,
            last_timestamp: result.last,
            duration_ms: duration_ns / 1_000_000.0
          }
        end

      {:error, _} ->
        nil
    end
  end

  defp calculate_max_drift(timing_stats) do
    # Calculate max drift as the difference between earliest start and latest start
    # across all files (indicating clock skew at capture time)

    if length(timing_stats) < 2 do
      0.0
    else
      first_timestamps =
        timing_stats
        |> Enum.map(& &1.first_timestamp)
        |> Enum.map(&Timestamp.to_unix_nanos/1)

      min_ts = Enum.min(first_timestamps)
      max_ts = Enum.max(first_timestamps)

      (max_ts - min_ts) / 1_000_000.0
    end
  end
end
