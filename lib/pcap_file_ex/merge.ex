defmodule PcapFileEx.Merge do
  @moduledoc """
  Multi-file PCAP/PCAPNG timeline merge with nanosecond precision.

  This module provides functionality to merge multiple packet capture files
  into a single chronological stream. Packets are sorted by nanosecond-precision
  timestamps, making it ideal for correlating captures from multiple network taps
  or synchronized systems.

  ## Clock Synchronization

  For accurate multi-file merging, ensure all capture systems have synchronized
  clocks using NTP (Network Time Protocol) or chronyd. See the README for
  chronyd setup instructions.

  ## Features

  - **Nanosecond precision**: Preserves full timestamp accuracy
  - **Memory efficient**: Streaming merge using priority queue (O(N files) memory)
  - **PCAP + PCAPNG**: Supports both formats, with PCAPNG interface remapping
  - **Datalink validation**: Ensures all files share compatible datalink types
  - **Source annotation**: Optionally track which file each packet came from
  - **Clock validation**: Optional validation of clock synchronization
  - **Configurable error handling**: `:skip`, `:halt`, or `:collect` modes

  ## Examples

      # Basic merge of two PCAP files
      {:ok, stream} = PcapFileEx.Merge.stream(["server1.pcap", "server2.pcap"])
      packets = Enum.to_list(stream)

      # Merge with source annotation
      {:ok, stream} = PcapFileEx.Merge.stream(
        ["tap1.pcap", "tap2.pcap"],
        annotate_source: true
      )

      Enum.each(stream, fn {packet, meta} ->
        IO.puts("Packet from \#{meta.source_file}")
      end)

      # Merge with clock validation
      case PcapFileEx.Merge.validate_clocks(["server1.pcap", "server2.pcap"]) do
        {:ok, stats} ->
          IO.inspect(stats.max_drift_ms)
          {:ok, stream} = PcapFileEx.Merge.stream(["server1.pcap", "server2.pcap"])
        {:error, :excessive_drift, meta} ->
          IO.puts("Clock drift too large: \#{meta.max_drift_ms}ms")
      end

      # Bang variant (raises on errors)
      stream = PcapFileEx.Merge.stream!(["server1.pcap", "server2.pcap"])

      # Count total packets across files
      count = PcapFileEx.Merge.count(["server1.pcap", "server2.pcap"])
  """

  alias PcapFileEx.Merge.{StreamMerger, Validator}

  @type path :: String.t()
  @type error_mode :: :skip | :halt | :collect
  @type merge_option ::
          {:annotate_source, boolean()}
          | {:on_error, error_mode()}
          | {:validate_clocks, boolean()}

  @doc """
  Creates a lazy stream that merges packets from multiple PCAP/PCAPNG files
  in chronological order.

  ## Parameters

  - `paths` - List of file paths to merge
  - `opts` - Keyword list of options:
    - `:annotate_source` (boolean, default: `false`) - Include source file metadata
    - `:on_error` (`:skip | :halt | :collect`, default: `:halt`) - Error handling mode
    - `:validate_clocks` (boolean, default: `false`) - Validate clock synchronization

  ## Returns

  - `{:ok, stream}` - Stream that emits merged packets
  - `{:error, reason}` - If validation fails

  ## Stream Item Types

  The stream emits different item types depending on options:

      # Default: bare packets
      stream([paths])
      # => %Packet{}, %Packet{}, ...

      # With annotation
      stream([paths], annotate_source: true)
      # => {%Packet{}, %{source_file: ...}}, ...

      # With :collect error mode
      stream([paths], on_error: :collect)
      # => {:ok, %Packet{}}, {:error, %{...}}, ...

      # With annotation + :collect (nested)
      stream([paths], annotate_source: true, on_error: :collect)
      # => {:ok, {%Packet{}, %{source_file: ...}}}, {:error, %{...}}, ...

      # With :skip mode
      stream([paths], on_error: :skip)
      # => %Packet{}, {:skipped_packet, %{count: 1, ...}}, %Packet{}, ...

  ## Examples

      {:ok, stream} = PcapFileEx.Merge.stream(["server1.pcap", "server2.pcap"])

      {:ok, stream} = PcapFileEx.Merge.stream(
        ["tap1.pcap", "tap2.pcap"],
        annotate_source: true,
        on_error: :collect
      )
  """
  @spec stream([path()], [merge_option()]) ::
          {:ok, Enumerable.t()} | {:error, term()}
  def stream(paths, opts \\ []) when is_list(paths) and is_list(opts) do
    with :ok <- validate_paths(paths),
         {:ok, _} <- Validator.validate_datalinks(paths) do
      annotate = Keyword.get(opts, :annotate_source, false)
      error_mode = Keyword.get(opts, :on_error, :skip)
      validate_clocks = Keyword.get(opts, :validate_clocks, false)

      if validate_clocks do
        case Validator.validate_clocks(paths) do
          {:ok, _stats} -> {:ok, build_stream(paths, annotate, error_mode)}
          error -> error
        end
      else
        {:ok, build_stream(paths, annotate, error_mode)}
      end
    end
  end

  @doc """
  Same as `stream/2` but raises on errors instead of returning error tuples.

  ## Examples

      stream = PcapFileEx.Merge.stream!(["server1.pcap", "server2.pcap"])

  ## Raises

  - `PcapFileEx.NoCommonDatalinkError` - When files have incompatible datalink types
  - `File.Error` - When a file cannot be opened
  - `ArgumentError` - When paths list is empty or invalid
  """
  @spec stream!([path()], [merge_option()]) :: Enumerable.t()
  def stream!(paths, opts \\ []) when is_list(paths) and is_list(opts) do
    case stream(paths, opts) do
      {:ok, stream} ->
        stream

      {:error, {:no_common_datalink, details}} ->
        raise PcapFileEx.NoCommonDatalinkError, details

      {:error, {:excessive_drift, details}} ->
        raise ArgumentError, "Excessive clock drift: #{details.max_drift_ms}ms"

      {:error, reason} ->
        raise ArgumentError, "Failed to create merge stream: #{inspect(reason)}"
    end
  end

  @doc """
  Validates clock synchronization across multiple capture files.

  This function performs a full scan of all files to collect timing statistics
  and detect potential clock drift between systems. It's useful for validating
  that captures were properly synchronized before merging.

  **Performance Note**: This function performs a full scan of all files and
  is NOT included in the merge overhead target. Results are cached by
  (file_path, mtime, size) to avoid repeated scans.

  ## Parameters

  - `paths` - List of file paths to validate

  ## Returns

  - `{:ok, stats}` - Validation succeeded, returns statistics map
  - `{:error, :excessive_drift, meta}` - Clock drift exceeds threshold

  ## Statistics Map

      %{
        max_drift_ms: float(),          # Maximum drift between any two files
        files: [
          %{
            path: String.t(),
            first_timestamp: Timestamp.t(),
            last_timestamp: Timestamp.t(),
            duration_ms: float()
          }
        ]
      }

  ## Examples

      case PcapFileEx.Merge.validate_clocks(["server1.pcap", "server2.pcap"]) do
        {:ok, stats} ->
          IO.puts("Max drift: \#{stats.max_drift_ms}ms")
        {:error, :excessive_drift, meta} ->
          IO.puts("Drift too large: \#{meta.max_drift_ms}ms")
      end
  """
  @spec validate_clocks([path()]) ::
          {:ok, map()} | {:error, :excessive_drift, map()}
  def validate_clocks(paths) when is_list(paths) do
    Validator.validate_clocks(paths)
  end

  @doc """
  Counts the total number of packets across multiple files without loading them.

  This is more efficient than merging and counting, as it only reads packet
  headers without full parsing.

  ## Examples

      count = PcapFileEx.Merge.count(["server1.pcap", "server2.pcap"])
      IO.puts("Total packets: \#{count}")
  """
  @spec count([path()]) :: non_neg_integer()
  def count(paths) when is_list(paths) do
    paths
    |> Enum.map(fn path ->
      # Use streaming count since Pcap.count/1 doesn't exist yet
      # Safe streams return {:ok, packet} tuples, so count those
      case PcapFileEx.stream(path) do
        {:ok, stream} ->
          Enum.count(stream, fn
            {:ok, _} -> true
            _ -> false
          end)

        _ ->
          0
      end
    end)
    |> Enum.sum()
  end

  # Private functions

  defp validate_paths([]), do: {:error, :empty_paths}

  defp validate_paths(paths) when is_list(paths) do
    case Enum.find(paths, &(!File.exists?(&1))) do
      nil -> :ok
      missing -> {:error, {:file_not_found, missing}}
    end
  end

  defp build_stream(paths, annotate, error_mode) do
    StreamMerger.merge(paths, annotate, error_mode)
  end
end
