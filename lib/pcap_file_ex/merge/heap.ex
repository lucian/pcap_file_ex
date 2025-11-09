defmodule PcapFileEx.Merge.Heap do
  @moduledoc """
  Min-heap priority queue for streaming packet merge.

  This module implements a priority queue optimized for merging multiple
  packet streams in chronological order. Each heap entry contains:
  - A packet
  - The file index (for deterministic tie-breaking)
  - The packet index within that file (for deterministic tie-breaking)

  ## Performance

  - `new/0`: O(1)
  - `push/2`: O(N) where N is the number of files (insert and sort)
  - `pop/1`: O(1) (remove first element)
  - Memory: O(N files) - only one packet buffered per file

  ## Ordering

  Packets are ordered by:
  1. `timestamp_precise` (primary key, nanosecond precision)
  2. `file_index` (secondary key, deterministic)
  3. `packet_index` (tertiary key, deterministic)

  This ensures a stable, reproducible sort even when packets have identical timestamps.

  ## Implementation Note

  This uses a sorted list rather than a true binary heap. For typical use cases
  with <10 files, this is simpler and performs well.
  """

  alias PcapFileEx.{Packet, Timestamp}

  @type heap_entry ::
          {Timestamp.t(), file_index :: non_neg_integer(), packet_index :: non_neg_integer(),
           Packet.t(), original_interface_id :: non_neg_integer() | nil}
  @type t :: [heap_entry()]

  @doc """
  Creates a new empty heap.

  ## Examples

      iex> PcapFileEx.Merge.Heap.new()
      []
  """
  @spec new() :: t()
  def new, do: []

  @doc """
  Checks if the heap is empty.

  ## Examples

      iex> PcapFileEx.Merge.Heap.new() |> PcapFileEx.Merge.Heap.empty?()
      true
  """
  @spec empty?(t()) :: boolean()
  def empty?([]), do: true
  def empty?(_), do: false

  @doc """
  Pushes a new packet onto the heap with its file and packet indices.

  ## Parameters

  - `heap` - The heap to push onto
  - `packet` - The packet to add
  - `file_index` - Index of the file this packet came from (for tie-breaking)
  - `packet_index` - Index of this packet within its file (for tie-breaking)
  - `original_interface_id` - Original interface ID before remapping (optional, for PCAPNG)

  ## Examples

      heap = PcapFileEx.Merge.Heap.new()
      heap = PcapFileEx.Merge.Heap.push(heap, packet, 0, 42, 0)
  """
  @spec push(t(), Packet.t(), non_neg_integer(), non_neg_integer(), non_neg_integer() | nil) ::
          t()
  def push(
        heap,
        %Packet{timestamp_precise: ts} = packet,
        file_index,
        packet_index,
        original_interface_id \\ nil
      ) do
    entry = {ts, file_index, packet_index, packet, original_interface_id}
    insert_sorted(heap, entry)
  end

  @doc """
  Removes and returns the minimum packet from the heap.

  Returns `{packet, file_index, packet_index, original_interface_id, new_heap}` or `:empty` if the heap is empty.

  ## Examples

      {packet, file_idx, pkt_idx, orig_iface_id, new_heap} = PcapFileEx.Merge.Heap.pop(heap)
  """
  @spec pop(t()) ::
          {Packet.t(), non_neg_integer(), non_neg_integer(), non_neg_integer() | nil, t()}
          | :empty
  def pop([]), do: :empty

  def pop([{_ts, file_idx, pkt_idx, packet, orig_iface_id} | rest]) do
    {packet, file_idx, pkt_idx, orig_iface_id, rest}
  end

  @doc """
  Returns the minimum packet without removing it.

  Returns `{packet, file_index, packet_index, original_interface_id}` or `:empty` if the heap is empty.

  ## Examples

      {packet, file_idx, pkt_idx, orig_iface_id} = PcapFileEx.Merge.Heap.peek(heap)
  """
  @spec peek(t()) ::
          {Packet.t(), non_neg_integer(), non_neg_integer(), non_neg_integer() | nil} | :empty
  def peek([]), do: :empty

  def peek([{_ts, file_idx, pkt_idx, packet, orig_iface_id} | _rest]) do
    {packet, file_idx, pkt_idx, orig_iface_id}
  end

  @doc """
  Returns the number of elements in the heap.

  ## Examples

      iex> heap = PcapFileEx.Merge.Heap.new()
      iex> PcapFileEx.Merge.Heap.size(heap)
      0
  """
  @spec size(t()) :: non_neg_integer()
  def size(heap), do: length(heap)

  # Private helper functions

  # Insert entry into sorted list maintaining order
  defp insert_sorted([], entry), do: [entry]

  defp insert_sorted([head | tail] = list, entry) do
    if compare_entries(entry, head) == :lt do
      [entry | list]
    else
      [head | insert_sorted(tail, entry)]
    end
  end

  # Compare two heap entries using (timestamp, file_index, packet_index) ordering
  defp compare_entries(
         {ts1, file_idx1, pkt_idx1, _packet1, _orig_iface1},
         {ts2, file_idx2, pkt_idx2, _packet2, _orig_iface2}
       ) do
    case Timestamp.compare(ts1, ts2) do
      :eq ->
        # Timestamps equal, use file_index for tie-breaking
        cond do
          file_idx1 < file_idx2 ->
            :lt

          file_idx1 > file_idx2 ->
            :gt

          true ->
            # File indices equal, use packet_index
            cond do
              pkt_idx1 < pkt_idx2 -> :lt
              pkt_idx1 > pkt_idx2 -> :gt
              true -> :eq
            end
        end

      other ->
        other
    end
  end
end
