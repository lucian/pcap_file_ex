defmodule PcapFileEx.Merge.InterfaceMapper do
  @moduledoc """
  PCAPNG interface ID remapping for multi-file merge.

  When merging multiple PCAPNG files, interface IDs can collide
  (e.g., file1.pcapng and file2.pcapng both have interface 0).
  This module builds a global mapping: {file_idx, orig_id} -> remapped_id.

  ## Example

      # Two files, each with interfaces 0 and 1
      mapping = InterfaceMapper.build_mapping(["f1.pcapng", "f2.pcapng"])
      # => %{
      #   {0, 0} => 0,  # File 0, interface 0 -> global 0
      #   {0, 1} => 1,  # File 0, interface 1 -> global 1
      #   {1, 0} => 2,  # File 1, interface 0 -> global 2
      #   {1, 1} => 3   # File 1, interface 1 -> global 3
      # }

  ## Remapping Logic

  For PCAP files (single interface):
  - No remapping needed (interface_id is always nil/0)
  - Mapping still created for consistency

  For PCAPNG files (multi-interface):
  - Each file's interface IDs are remapped to unique global IDs
  - Remapping applied before packets enter merge heap
  - Original interface ID preserved in annotation metadata
  """

  alias PcapFileEx.{Packet, PcapNg}

  @doc """
  Builds a global interface ID mapping for all files.

  Scans each file to extract interface declarations and assigns
  unique global IDs to prevent collisions during merge.

  ## Parameters

  - `paths` - List of file paths to merge
  - `file_states` - List of file state maps with reader and format info

  ## Returns

  Map of `{file_idx, original_interface_id} => global_interface_id`

  ## Examples

      mapping = InterfaceMapper.build_mapping(file_states)
      # => %{{0, 0} => 0, {0, 1} => 1, {1, 0} => 2}
  """
  @spec build_mapping([map()]) :: %{
          {non_neg_integer(), non_neg_integer()} => non_neg_integer()
        }
  def build_mapping(file_states) do
    {mapping, _next_global_id} =
      file_states
      |> Enum.reduce({%{}, 0}, fn file_state, {acc_mapping, next_id} ->
        case file_state.format do
          :pcap ->
            # PCAP has single implicit interface (ID 0)
            # Map {file_idx, 0} => next_global_id
            new_mapping = Map.put(acc_mapping, {file_state.file_index, 0}, next_id)
            {new_mapping, next_id + 1}

          :pcapng ->
            # PCAPNG can have multiple interfaces, scan them
            case PcapNg.interfaces(file_state.reader) do
              {:ok, interfaces} ->
                # Assign sequential global IDs to each interface
                {new_mapping, final_id} =
                  interfaces
                  |> Enum.reduce({acc_mapping, next_id}, fn iface, {map_acc, global_id} ->
                    key = {file_state.file_index, iface.id}
                    updated_map = Map.put(map_acc, key, global_id)
                    {updated_map, global_id + 1}
                  end)

                {new_mapping, final_id}

              {:error, _} ->
                # If can't read interfaces, assume single interface 0
                new_mapping = Map.put(acc_mapping, {file_state.file_index, 0}, next_id)
                {new_mapping, next_id + 1}
            end
        end
      end)

    mapping
  end

  @doc """
  Remaps a packet's interface ID using the global mapping.

  ## Parameters

  - `packet` - Packet struct to remap
  - `file_idx` - Index of the file this packet came from
  - `mapping` - Global interface mapping

  ## Returns

  `{remapped_packet, original_interface_id}`

  For PCAP packets (no interface_id field), returns {packet, 0}
  For PCAPNG packets, returns {packet_with_remapped_id, original_id}

  ## Examples

      mapping = %{{0, 0} => 0, {0, 1} => 1, {1, 0} => 2}
      packet = %Packet{interface_id: 0, ...}  # From file 1

      {remapped, orig_id} = InterfaceMapper.remap_packet(packet, 1, mapping)
      # => {%Packet{interface_id: 2, ...}, 0}
  """
  @spec remap_packet(Packet.t(), non_neg_integer(), map()) ::
          {Packet.t(), non_neg_integer()}
  def remap_packet(%Packet{} = packet, file_idx, mapping) do
    # Get original interface ID (0 if not set for PCAP files)
    original_id = packet.interface_id || 0

    # Look up global ID in mapping
    key = {file_idx, original_id}

    case Map.fetch(mapping, key) do
      {:ok, global_id} ->
        # Remap to global ID - update BOTH packet.interface_id AND packet.interface.id
        # to maintain invariant: packet.interface_id == packet.interface.id
        remapped_packet =
          if packet.interface do
            # PCAPNG packet - clone Interface struct with remapped id
            remapped_interface = %{packet.interface | id: global_id}
            %{packet | interface_id: global_id, interface: remapped_interface}
          else
            # PCAP packet - no Interface struct to update
            %{packet | interface_id: global_id}
          end

        {remapped_packet, original_id}

      :error ->
        # No mapping found (shouldn't happen), return unchanged
        {packet, original_id}
    end
  end
end
