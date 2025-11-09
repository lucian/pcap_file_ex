defmodule PcapFileEx.TimestampShift do
  @moduledoc """
  Utilities for shifting packet timestamps.

  Useful for:
  - Normalizing timestamps to start at epoch (for reproducible tests)
  - Anonymizing capture times
  - Aligning captures from different sources

  ## Examples

      # Normalize timestamps to start at epoch
      normalized = PcapFileEx.TimestampShift.normalize_to_epoch(packets)

      # Shift all timestamps by a fixed offset
      shifted = PcapFileEx.TimestampShift.shift_all(packets, -3_600_000_000_000)  # -1 hour in nanos
  """

  alias PcapFileEx.{Packet, Timestamp}

  @doc """
  Shifts all packet timestamps by a fixed nanosecond offset.

  ## Parameters

    * `packets` - Enumerable of packets
    * `offset_nanos` - Nanoseconds to add (negative to subtract)

  ## Returns

    * List of packets with adjusted timestamps

  ## Examples

      # Shift forward by 1 second
      shifted = PcapFileEx.TimestampShift.shift_all(packets, 1_000_000_000)

      # Shift backward by 1 hour
      shifted = PcapFileEx.TimestampShift.shift_all(packets, -3_600_000_000_000)
  """
  @spec shift_all(Enumerable.t(), integer()) :: [Packet.t()]
  def shift_all(packets, offset_nanos) when is_integer(offset_nanos) do
    Enum.map(packets, fn packet ->
      shift_packet(packet, offset_nanos)
    end)
  end

  @doc """
  Normalizes timestamps so the first packet starts at Unix epoch (1970-01-01 00:00:00 UTC).

  Calculates the offset needed to move the first packet to epoch, then applies
  that offset to all packets. Preserves relative timing between packets.

  ## Parameters

    * `packets` - Enumerable of packets (must have at least one packet)

  ## Returns

    * List of packets with normalized timestamps

  ## Examples

      # Make timestamps start at epoch
      normalized = PcapFileEx.TimestampShift.normalize_to_epoch(packets)

      # First packet will have timestamp_precise.secs == 0
      [first | _rest] = normalized
      assert first.timestamp_precise.secs == 0
  """
  @spec normalize_to_epoch(Enumerable.t()) :: [Packet.t()]
  def normalize_to_epoch(packets) do
    packets_list = Enum.to_list(packets)

    case packets_list do
      [] ->
        []

      [first | _rest] ->
        # Calculate offset to move first packet to epoch
        first_ts = first.timestamp_precise
        offset_nanos = -(first_ts.secs * 1_000_000_000 + first_ts.nanos)

        shift_all(packets_list, offset_nanos)
    end
  end

  # Private helper to shift a single packet
  defp shift_packet(%Packet{} = packet, offset_nanos) do
    ts = packet.timestamp_precise

    # Convert to total nanoseconds
    total_nanos = ts.secs * 1_000_000_000 + ts.nanos + offset_nanos

    # Handle negative timestamps (clamp to epoch)
    total_nanos = max(0, total_nanos)

    # Split back into secs and nanos
    new_secs = div(total_nanos, 1_000_000_000)
    new_nanos = rem(total_nanos, 1_000_000_000)

    # Create new timestamp
    new_timestamp_precise = Timestamp.new(new_secs, new_nanos)

    # Also update DateTime timestamp (for backward compatibility)
    new_timestamp = DateTime.from_unix!(new_secs, :second)
    new_timestamp = DateTime.add(new_timestamp, div(new_nanos, 1000), :microsecond)

    %{packet | timestamp: new_timestamp, timestamp_precise: new_timestamp_precise}
  end
end
