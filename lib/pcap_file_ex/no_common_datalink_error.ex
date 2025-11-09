defmodule PcapFileEx.NoCommonDatalinkError do
  @moduledoc """
  Exception raised when attempting to merge files with incompatible datalink types.

  This error occurs during multi-file merge operations when:
  - PCAP files have different global datalink types
  - PCAPNG files have active interfaces with non-shared datalink types

  The exception includes detailed information about which files and interfaces
  are incompatible.
  """

  defexception [:message, :details]

  @impl true
  def exception(details) when is_map(details) do
    message = build_message(details)
    %__MODULE__{message: message, details: details}
  end

  defp build_message(details) do
    base = "Cannot merge files: no common datalink type found.\n"

    incompatible =
      if Map.has_key?(details, :incompatible_interfaces) do
        interfaces = details.incompatible_interfaces

        interfaces_str =
          Enum.map_join(interfaces, "\n", fn iface ->
            "  - #{iface.file}: interface #{iface.interface_id} " <>
              "(#{iface.datalink}, #{iface.packet_count} packets)"
          end)

        "\nIncompatible interfaces:\n#{interfaces_str}\n"
      else
        files = details[:files] || []

        files_str =
          Enum.map_join(files, "\n", fn file ->
            "  - #{file.path}: #{file.datalink || "mixed interfaces"}"
          end)

        "\nIncompatible files:\n#{files_str}\n"
      end

    suggestion =
      "\nTo merge these files, ensure all active interfaces share a common datalink type.\n" <>
        "For PCAPNG files with unused interface declarations, only interfaces that\n" <>
        "actually emitted packets (packet_count > 0) are validated."

    base <> incompatible <> suggestion
  end
end
