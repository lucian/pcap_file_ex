defmodule PcapFileEx.ComptimeUtils do
  @moduledoc false
  # Utilities for compile-time CPU capability detection

  @doc """
  Checks if the current CPU has all the specified capabilities.

  This function reads the CPU information from `/proc/cpuinfo` (Linux only)
  and checks if all the specified flags are present.

  ## Parameters

    * `needed_flags` - A list of CPU capability flags to check for
    * `opts` - Optional keyword list with:
      * `:cpu_info_file_path` - Custom path to CPU info file (default: "/proc/cpuinfo")
      * `:target` - Target platform (currently unused, for future cross-compilation support)

  ## Returns

    * `true` if all needed flags are present in the CPU
    * `false` if any flag is missing or if CPU info cannot be read

  ## Examples

      iex> PcapFileEx.ComptimeUtils.cpu_with_all_caps?(~w[sse sse2])
      true

      iex> PcapFileEx.ComptimeUtils.cpu_with_all_caps?(~w[avx512f])
      false

  """
  def cpu_with_all_caps?(needed_flags, opts \\ []) do
    cpu_info_path = opts[:cpu_info_file_path] || "/proc/cpuinfo"

    case File.read(cpu_info_path) do
      {:ok, contents} ->
        cpu_flags = parse_cpu_flags(contents)
        Enum.all?(needed_flags, fn flag -> flag in cpu_flags end)

      {:error, _reason} ->
        # If we can't read the CPU info file (e.g., not on Linux),
        # assume the CPU doesn't have the required capabilities
        false
    end
  end

  # Parse CPU flags from /proc/cpuinfo
  defp parse_cpu_flags(contents) do
    contents
    |> String.split("\n")
    |> Stream.map(&String.trim/1)
    |> Stream.filter(&String.starts_with?(&1, "flags"))
    |> Stream.take(1)
    |> Enum.to_list()
    |> case do
      [flags_line] ->
        flags_line
        |> String.split(":", parts: 2)
        |> List.last()
        |> String.split()
        |> MapSet.new()

      [] ->
        MapSet.new()
    end
  end
end
