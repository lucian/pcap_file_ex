defmodule PcapFileEx.Merge.ValidationCache do
  @moduledoc """
  File-based cache for PCAP/PCAPNG timing statistics.

  This module provides a simple disk-based cache to avoid repeatedly scanning
  large PCAP files during `validate_clocks/1` calls. Cache entries are keyed
  by (file_path, mtime, size) to automatically invalidate when files change.

  ## Cache Location

  Cache files are stored in: `System.tmp_dir!() <> "/pcap_merge_cache/"`

  ## Cache Format

  - **Key**: `:erlang.phash2({path, mtime, size})` as filename
  - **Value**: ETF (Erlang Term Format) serialized timing stats map
  - **Invalidation**: Automatic when file mtime or size changes

  ## Performance Impact

  For large files (>1GB), cache hits can reduce validation time from seconds
  to milliseconds. The cache persists across process restarts.

  ## Examples

      # Get cached stats (returns nil if not cached or invalidated)
      stats = ValidationCache.get("/path/to/capture.pcap")

      # Store stats after scanning
      stats = %{path: "...", first_timestamp: ..., last_timestamp: ..., duration_ms: ...}
      ValidationCache.put("/path/to/capture.pcap", stats)

      # Clear all cache entries
      ValidationCache.clear_all()
  """

  require Logger

  @cache_dir Path.join(System.tmp_dir!(), "pcap_merge_cache")

  @doc """
  Gets cached timing statistics for a file.

  Returns `nil` if:
  - No cache entry exists
  - File has been modified since caching (mtime or size changed)
  - Cache directory doesn't exist
  - Cache read fails

  ## Parameters

  - `path` - Absolute path to the PCAP/PCAPNG file

  ## Examples

      case ValidationCache.get("/captures/server1.pcap") do
        nil -> # Cache miss, need to scan file
        stats -> # Cache hit, use cached stats
      end
  """
  @spec get(String.t()) :: map() | nil
  def get(path) do
    with {:ok, file_info} <- File.stat(path),
         cache_key <- build_cache_key(path, file_info),
         cache_file <- cache_file_path(cache_key),
         {:ok, binary} <- File.read(cache_file),
         stats <- :erlang.binary_to_term(binary) do
      stats
    else
      _ ->
        # Cache miss or read error
        nil
    end
  end

  @doc """
  Stores timing statistics in the cache.

  Creates cache directory if it doesn't exist. Silently fails if cache
  write errors occur (cache is optional, not critical).

  ## Parameters

  - `path` - Absolute path to the PCAP/PCAPNG file
  - `stats` - Timing statistics map to cache

  ## Examples

      stats = %{
        path: "/captures/server1.pcap",
        first_timestamp: %Timestamp{...},
        last_timestamp: %Timestamp{...},
        duration_ms: 123.456
      }

      ValidationCache.put("/captures/server1.pcap", stats)
  """
  @spec put(String.t(), map()) :: :ok
  def put(path, stats) do
    with {:ok, file_info} <- File.stat(path),
         :ok <- ensure_cache_dir(),
         cache_key <- build_cache_key(path, file_info),
         cache_file <- cache_file_path(cache_key),
         binary <- :erlang.term_to_binary(stats),
         :ok <- File.write(cache_file, binary) do
      :ok
    else
      error ->
        # Log cache write failures but don't raise
        Logger.debug("Failed to write validation cache: #{inspect(error)}")
        :ok
    end
  end

  @doc """
  Clears all cached validation data.

  Removes all cache files from the cache directory. Useful for testing
  or recovering from cache corruption.

  ## Examples

      ValidationCache.clear_all()
      # => :ok (all cache files deleted)
  """
  @spec clear_all() :: :ok
  def clear_all do
    if File.exists?(@cache_dir) do
      case File.rm_rf(@cache_dir) do
        {:ok, _files} ->
          :ok

        {:error, reason, _file} ->
          Logger.warning("Failed to clear validation cache: #{inspect(reason)}")
          :ok
      end
    else
      :ok
    end
  end

  # Private functions

  defp build_cache_key(path, %File.Stat{mtime: mtime, size: size}) do
    # Use phash2 for consistent integer hash
    :erlang.phash2({path, mtime, size})
  end

  defp cache_file_path(key) do
    Path.join(@cache_dir, "#{key}.etf")
  end

  defp ensure_cache_dir do
    File.mkdir_p(@cache_dir)
  end
end
