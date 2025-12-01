defmodule PcapFileEx.MergeTest do
  use ExUnit.Case, async: true
  doctest PcapFileEx.Merge

  alias PcapFileEx.{Merge, Timestamp}

  # Use files with compatible datalink types
  # sample.pcap has "null" datalink
  # linux_new_test.pcap has "ethernet" datalink
  # Let's use the same file twice for testing merge logic
  @sample_pcap "test/fixtures/sample.pcap"
  @sample_pcapng "test/fixtures/sample.pcapng"
  @sample2_pcap "test/fixtures/sample.pcap"

  describe "stream/2" do
    test "merges two PCAP files in chronological order" do
      {:ok, stream} = Merge.stream([@sample_pcap, @sample_pcap])

      packets = Enum.to_list(stream)

      # Should have packets from both files
      refute Enum.empty?(packets)

      # Verify chronological order
      assert_chronological_order(packets)
    end

    test "merges PCAP and PCAPNG files together" do
      {:ok, stream} = Merge.stream([@sample_pcap, @sample_pcapng])

      packets = Enum.to_list(stream)

      refute Enum.empty?(packets)
      assert_chronological_order(packets)
    end

    test "returns error for empty paths list" do
      assert {:error, :empty_paths} = Merge.stream([])
    end

    test "returns error for non-existent file" do
      assert {:error, {:file_not_found, _}} = Merge.stream(["nonexistent.pcap"])
    end

    test "merges with source annotation" do
      {:ok, stream} = Merge.stream([@sample_pcap, @sample2_pcap], annotate_source: true)

      packets = Enum.take(stream, 5)

      # Each packet should be a tuple {packet, metadata}
      Enum.each(packets, fn {packet, metadata} ->
        assert %PcapFileEx.Packet{} = packet
        assert is_map(metadata)
        assert Map.has_key?(metadata, :source_file)
        assert Map.has_key?(metadata, :file_index)
        assert Map.has_key?(metadata, :packet_index)
        assert metadata.source_file in [@sample_pcap, @sample2_pcap]
      end)
    end

    test "merges PCAPNG with annotation includes interface IDs" do
      {:ok, stream} = Merge.stream([@sample_pcapng, @sample_pcapng], annotate_source: true)

      packets = Enum.take(stream, 5)

      # PCAPNG packets should include both original and remapped interface IDs
      Enum.each(packets, fn {packet, metadata} ->
        assert %PcapFileEx.Packet{} = packet
        assert is_map(metadata)
        # Basic metadata fields
        assert Map.has_key?(metadata, :source_file)
        assert Map.has_key?(metadata, :file_index)
        assert Map.has_key?(metadata, :packet_index)
        # PCAPNG-specific interface ID fields
        assert Map.has_key?(metadata, :original_interface_id),
               "Missing :original_interface_id in metadata"

        assert Map.has_key?(metadata, :remapped_interface_id),
               "Missing :remapped_interface_id in metadata"

        # Verify remapped ID matches packet.interface_id
        assert metadata.remapped_interface_id == packet.interface_id,
               "remapped_interface_id (#{metadata.remapped_interface_id}) != packet.interface_id (#{packet.interface_id})"

        # Verify invariant: packet.interface_id == packet.interface.id
        if packet.interface do
          assert packet.interface_id == packet.interface.id,
                 "Invariant broken: packet.interface_id (#{packet.interface_id}) != packet.interface.id (#{packet.interface.id})"
        end
      end)
    end

    test "merges with :collect error mode" do
      {:ok, stream} = Merge.stream([@sample_pcap, @sample2_pcap], on_error: :collect)

      packets = Enum.take(stream, 5)

      # Each item should be {:ok, packet}
      Enum.each(packets, fn item ->
        assert {:ok, packet} = item
        assert %PcapFileEx.Packet{} = packet
      end)
    end

    test "merges with annotation and :collect mode (nested tuples)" do
      {:ok, stream} =
        Merge.stream(
          [@sample_pcap, @sample2_pcap],
          annotate_source: true,
          on_error: :collect
        )

      packets = Enum.take(stream, 5)

      # Each item should be {:ok, {packet, metadata}}
      Enum.each(packets, fn item ->
        assert {:ok, {packet, metadata}} = item
        assert %PcapFileEx.Packet{} = packet
        assert is_map(metadata)
        assert Map.has_key?(metadata, :source_file)
      end)
    end
  end

  describe "stream!/2" do
    test "returns stream for valid files" do
      stream = Merge.stream!([@sample_pcap, @sample2_pcap])

      packets = Enum.take(stream, 5)
      assert length(packets) == 5
      assert_chronological_order(packets)
    end

    test "raises ArgumentError for empty paths" do
      assert_raise ArgumentError, fn ->
        Merge.stream!([])
      end
    end

    test "raises ArgumentError for non-existent file" do
      assert_raise ArgumentError, fn ->
        Merge.stream!(["nonexistent.pcap"])
      end
    end
  end

  describe "validate_clocks/1" do
    test "validates clock synchronization for multiple files" do
      case Merge.validate_clocks([@sample_pcap, @sample2_pcap]) do
        {:ok, stats} ->
          assert is_map(stats)
          assert Map.has_key?(stats, :max_drift_ms)
          assert Map.has_key?(stats, :files)
          assert is_float(stats.max_drift_ms)
          assert is_list(stats.files)

        {:error, :excessive_drift, meta} ->
          # Acceptable if files have excessive drift
          assert is_map(meta)
          assert Map.has_key?(meta, :max_drift_ms)
      end
    end

    test "returns ok for single file" do
      {:ok, stats} = Merge.validate_clocks([@sample_pcap])

      assert stats.max_drift_ms == 0.0
    end

    test "returns ok for empty list" do
      {:ok, stats} = Merge.validate_clocks([])

      assert stats.max_drift_ms == 0.0
      assert stats.files == []
    end
  end

  describe "count/1" do
    test "counts total packets across multiple files" do
      count = Merge.count([@sample_pcap, @sample2_pcap])

      # Should be sum of both files (same file twice, so 2x count)
      {:ok, stream} = PcapFileEx.stream(@sample_pcap)

      single_count =
        Enum.count(stream, fn
          {:ok, _} -> true
          _ -> false
        end)

      assert count == single_count * 2
    end

    test "returns 0 for empty paths list" do
      assert Merge.count([]) == 0
    end

    test "returns 0 for non-existent files" do
      assert Merge.count(["nonexistent.pcap"]) == 0
    end
  end

  describe "nanosecond precision merge" do
    setup do
      # Create temporary files for nanosecond precision testing
      temp_dir = System.tmp_dir!()
      test_id = :erlang.unique_integer([:positive])

      nano_file1 = Path.join(temp_dir, "nano_merge_1_#{test_id}.pcapng")
      nano_file2 = Path.join(temp_dir, "nano_merge_2_#{test_id}.pcapng")

      on_exit(fn ->
        File.rm(nano_file1)
        File.rm(nano_file2)
      end)

      {:ok, nano_file1: nano_file1, nano_file2: nano_file2}
    end

    test "merges PCAPNG files with nanosecond timestamps in correct order", %{
      nano_file1: file1,
      nano_file2: file2
    } do
      # Create interface with nanosecond resolution
      interface = %PcapFileEx.Interface{
        id: 0,
        linktype: "ethernet",
        snaplen: 65_535,
        timestamp_resolution: :nanosecond,
        timestamp_resolution_raw: "nanosecond",
        timestamp_offset_secs: 0
      }

      # File 1: odd nanoseconds (1, 3, 5)
      packets1 = [
        create_nano_packet(1000, 1, 0),
        create_nano_packet(1000, 3, 0),
        create_nano_packet(1000, 5, 0)
      ]

      # File 2: even nanoseconds (2, 4, 6)
      packets2 = [
        create_nano_packet(1000, 2, 0),
        create_nano_packet(1000, 4, 0),
        create_nano_packet(1000, 6, 0)
      ]

      # Write PCAPNG files
      {:ok, 3} = PcapFileEx.PcapNgWriter.write_all(file1, [interface], packets1)
      {:ok, 3} = PcapFileEx.PcapNgWriter.write_all(file2, [interface], packets2)

      # Merge the files
      {:ok, stream} = Merge.stream([file1, file2])
      merged_packets = Enum.to_list(stream)

      # Verify count
      assert length(merged_packets) == 6

      # Verify nanosecond-level ordering: 1, 2, 3, 4, 5, 6
      expected_nanos = [1, 2, 3, 4, 5, 6]
      actual_nanos = Enum.map(merged_packets, & &1.timestamp_precise.nanos)

      assert actual_nanos == expected_nanos,
             "Expected nanosecond order #{inspect(expected_nanos)}, got #{inspect(actual_nanos)}"

      # Verify all have same second component
      assert Enum.all?(merged_packets, &(&1.timestamp_precise.secs == 1000))

      # Verify chronological ordering (redundant but explicit)
      assert_chronological_order(merged_packets)
    end

    # Helper function for creating nanosecond-precise packets
    defp create_nano_packet(secs, nanos, interface_id) do
      %PcapFileEx.Packet{
        timestamp_precise: Timestamp.new(secs, nanos),
        timestamp: DateTime.from_unix!(secs, :second),
        orig_len: 60,
        data: <<0::480>>,
        datalink: "ethernet",
        timestamp_resolution: :nanosecond,
        interface_id: interface_id,
        interface: nil
      }
    end
  end

  # Helper functions

  defp assert_chronological_order(packets) do
    packets
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.each(fn [p1, p2] ->
      assert Timestamp.compare(p1.timestamp_precise, p2.timestamp_precise) in [:lt, :eq],
             "Packets not in chronological order: #{inspect(p1.timestamp_precise)} > #{inspect(p2.timestamp_precise)}"
    end)
  end
end
