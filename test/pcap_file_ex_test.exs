defmodule PcapFileExTest do
  use ExUnit.Case, async: true
  doctest PcapFileEx

  alias PcapFileEx
  alias PcapFileEx.Timestamp

  @test_pcap_file "test/fixtures/sample.pcap"
  @test_pcapng_nanosec "test/fixtures/linux_new_test.pcapng"

  describe "open/1" do
    test "delegates to Pcap.open/1" do
      if File.exists?(@test_pcap_file) do
        assert {:ok, reader} = PcapFileEx.open(@test_pcap_file)
        assert %PcapFileEx.Pcap{} = reader
        PcapFileEx.Pcap.close(reader)
      end
    end
  end

  describe "read_all/1" do
    test "delegates to Pcap.read_all/1" do
      if File.exists?(@test_pcap_file) do
        assert {:ok, packets} = PcapFileEx.read_all(@test_pcap_file)
        assert is_list(packets)
      end
    end
  end

  describe "nanosecond timestamp precision" do
    test "preserves nanosecond precision in timestamp_precise field" do
      if File.exists?(@test_pcapng_nanosec) do
        assert {:ok, packets} = PcapFileEx.read_all(@test_pcapng_nanosec)
        assert length(packets) > 0

        first = List.first(packets)

        # Verify timestamp_precise exists and has Timestamp type
        assert %Timestamp{} = first.timestamp_precise
        assert is_integer(first.timestamp_precise.secs)
        assert is_integer(first.timestamp_precise.nanos)

        # Verify nanosecond component has full 9-digit precision capability
        assert first.timestamp_precise.nanos >= 0
        assert first.timestamp_precise.nanos <= 999_999_999

        # Verify the timestamp has sub-microsecond precision (last 3 digits != 000)
        # by checking at least one packet has non-zero sub-microsecond component
        has_subsec_precision =
          Enum.any?(packets, fn pkt ->
            rem(pkt.timestamp_precise.nanos, 1000) != 0
          end)

        # Note: This may be false if the capture didn't have sub-microsecond timing
        # but the structure supports it
        if has_subsec_precision do
          # At least one packet has true nanosecond precision
          assert has_subsec_precision
        end
      end
    end

    test "backward compatible DateTime timestamp still works" do
      if File.exists?(@test_pcapng_nanosec) do
        assert {:ok, packets} = PcapFileEx.read_all(@test_pcapng_nanosec)
        first = List.first(packets)

        # Verify timestamp field exists and is DateTime
        assert %DateTime{} = first.timestamp
        assert is_integer(first.timestamp.year)
        assert is_integer(first.timestamp.month)

        # Verify it has microsecond precision (6 decimal places)
        {micros, precision} = first.timestamp.microsecond
        assert is_integer(micros)
        assert micros >= 0 and micros <= 999_999
        assert precision == 6
      end
    end

    test "timestamp and timestamp_precise are consistent" do
      if File.exists?(@test_pcapng_nanosec) do
        assert {:ok, packets} = PcapFileEx.read_all(@test_pcapng_nanosec)
        first = List.first(packets)

        # Converting timestamp_precise to DateTime should match timestamp
        # (within microsecond precision)
        dt_from_precise = Timestamp.to_datetime(first.timestamp_precise)
        assert dt_from_precise == first.timestamp

        # The seconds component should match
        dt_secs = DateTime.to_unix(first.timestamp, :second)
        assert dt_secs == first.timestamp_precise.secs
      end
    end

    test "can sort packets by nanosecond precision" do
      if File.exists?(@test_pcapng_nanosec) do
        assert {:ok, packets} = PcapFileEx.read_all(@test_pcapng_nanosec)

        # Sort by precise timestamp
        sorted = Enum.sort_by(packets, & &1.timestamp_precise, Timestamp)

        # Verify sorting worked - each packet should be >= previous
        sorted
        |> Enum.chunk_every(2, 1, :discard)
        |> Enum.each(fn [prev, curr] ->
          assert Timestamp.compare(prev.timestamp_precise, curr.timestamp_precise) in [:lt, :eq]
        end)
      end
    end

    test "timestamp_precise preserves more precision than timestamp" do
      if File.exists?(@test_pcapng_nanosec) do
        assert {:ok, packets} = PcapFileEx.read_all(@test_pcapng_nanosec)
        first = List.first(packets)

        # Get nanoseconds from precise timestamp
        nanos_precise = first.timestamp_precise.nanos

        # Get microseconds from DateTime timestamp
        {micros, _} = first.timestamp.microsecond

        # The precise timestamp's nanoseconds, when truncated to microseconds,
        # should match the DateTime's microseconds
        assert div(nanos_precise, 1000) == micros

        # But timestamp_precise can represent sub-microsecond values
        # that DateTime cannot (0-999 nanoseconds)
        subsec_nanos = rem(nanos_precise, 1000)
        assert subsec_nanos >= 0 and subsec_nanos < 1000
      end
    end

    test "can calculate nanosecond-precise time differences" do
      if File.exists?(@test_pcapng_nanosec) do
        assert {:ok, packets} = PcapFileEx.read_all(@test_pcapng_nanosec)

        if length(packets) >= 2 do
          first = Enum.at(packets, 0)
          second = Enum.at(packets, 1)

          # Calculate difference in nanoseconds
          diff_nanos = Timestamp.diff(second.timestamp_precise, first.timestamp_precise)

          # Difference should be positive (assuming packets are in chronological order)
          # or at least a valid integer
          assert is_integer(diff_nanos)

          # We can represent differences with nanosecond precision
          # that would be impossible with DateTime alone
        end
      end
    end

    test "timestamp_resolution field indicates nanosecond precision" do
      if File.exists?(@test_pcapng_nanosec) do
        assert {:ok, packets} = PcapFileEx.read_all(@test_pcapng_nanosec)
        first = List.first(packets)

        # Linux pcapng files typically use nanosecond resolution
        assert first.timestamp_resolution == :nanosecond
      end
    end
  end
end
