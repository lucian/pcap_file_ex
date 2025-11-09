defmodule PcapFileEx.BugRegressionTest do
  @moduledoc """
  Regression tests for bugs fixed in Version 1.4 (Post-Implementation Bug Fixes).

  Tests verify that:
  - Format.detect/1 errors are properly handled (bugs 1-2, 7-8)
  - Resources are properly cleaned up (bugs 3-4)
  - Tuple unwrapping works correctly (bugs 5-6)
  """
  use ExUnit.Case, async: true

  alias PcapFileEx

  @moduletag :regression

  describe "Bug 1-2: Format.detect error handling in copy/export_filtered" do
    test "copy/3 returns error for unreadable file instead of crashing" do
      # Bug: CaseClauseError when Format.detect returns {:error, reason}
      # Fix: Proper error handling with with chain
      nonexistent_file = "/tmp/nonexistent_file_#{:rand.uniform(1_000_000)}.pcap"
      output_file = "/tmp/output_#{:rand.uniform(1_000_000)}.pcap"

      # Should return error tuple, not crash
      assert {:error, reason} = PcapFileEx.copy(nonexistent_file, output_file)
      assert is_binary(reason)
      assert String.contains?(reason, "Cannot open file") or String.contains?(reason, "not found")
    end

    test "export_filtered/4 returns error for unreadable file instead of crashing" do
      # Same bug as copy/3
      nonexistent_file = "/tmp/nonexistent_file_#{:rand.uniform(1_000_000)}.pcap"
      output_file = "/tmp/output_#{:rand.uniform(1_000_000)}.pcap"
      filter_fun = fn _packet -> true end

      # Should return error tuple, not crash
      assert {:error, reason} =
               PcapFileEx.export_filtered(nonexistent_file, output_file, filter_fun)

      assert is_binary(reason)
      assert String.contains?(reason, "Cannot open file") or String.contains?(reason, "not found")
    end

    test "copy/3 returns error for file with unknown format" do
      # Create a file with invalid magic number
      invalid_file = "/tmp/invalid_#{:rand.uniform(1_000_000)}.pcap"
      File.write!(invalid_file, "INVALID_MAGIC_NUMBER_HERE")

      on_exit(fn -> File.rm(invalid_file) end)

      output_file = "/tmp/output_#{:rand.uniform(1_000_000)}.pcap"

      assert {:error, reason} = PcapFileEx.copy(invalid_file, output_file)
      assert is_binary(reason)
      assert String.contains?(reason, "Unknown file format") or String.contains?(reason, "magic")
    end
  end

  describe "Bug 3-4: Resource cleanup in get_header" do
    test "copy/3 does not leak file descriptors" do
      # Bug: Missing Pcap.close/PcapNg.close calls
      # Fix: try/after blocks to ensure cleanup

      test_file = Path.join([__DIR__, "..", "fixtures", "sample.pcap"])

      # Get initial port count
      initial_port_count = :erlang.system_info(:port_count)

      # Perform multiple copy operations
      Enum.each(1..10, fn i ->
        output_file = "/tmp/output_#{i}_#{:rand.uniform(1_000_000)}.pcap"

        # Copy file (internally calls get_header which opens readers)
        {:ok, _count} = PcapFileEx.copy(test_file, output_file)

        # Clean up
        File.rm(output_file)
      end)

      # Force garbage collection to close any lingering resources
      :erlang.garbage_collect()
      Process.sleep(100)

      # Get final port count
      final_port_count = :erlang.system_info(:port_count)

      # Port count should not have increased significantly
      # Allow small variance (±2) for test infrastructure ports
      port_diff = final_port_count - initial_port_count

      assert abs(port_diff) <= 2,
             "File descriptor leak detected: #{initial_port_count} -> #{final_port_count} (diff: #{port_diff})"
    end
  end

  describe "Bug 5-6: PCAPNG tuple unwrapping" do
    test "copy/3 works with PCAPNG files" do
      # Bug: List.first called on {:ok, list} tuple
      # Bug: extract_interfaces_from_reader returns {:ok, {:ok, list}}
      # Fix: Proper tuple unwrapping

      # Create a minimal PCAPNG file for testing
      output_pcapng = "/tmp/test_#{:rand.uniform(1_000_000)}.pcapng"
      copy_pcap = "/tmp/copy_#{:rand.uniform(1_000_000)}.pcap"

      on_exit(fn ->
        File.rm(output_pcapng)
        File.rm(copy_pcap)
      end)

      # Create PCAPNG with interface
      interface = %PcapFileEx.Interface{
        id: 0,
        linktype: "ethernet",
        snaplen: 65_535,
        name: "eth0",
        timestamp_resolution: :microsecond,
        timestamp_resolution_raw: "microsecond",
        timestamp_offset_secs: 0
      }

      packet = %PcapFileEx.Packet{
        timestamp: ~U[2025-11-09 10:00:00Z],
        timestamp_precise: %PcapFileEx.Timestamp{secs: 1_731_146_400, nanos: 0},
        orig_len: 100,
        data: <<1, 2, 3, 4, 5>>,
        datalink: "ethernet",
        timestamp_resolution: :microsecond,
        interface_id: 0,
        interface: nil
      }

      # Create initial PCAPNG file
      {:ok, _count} = PcapFileEx.PcapNgWriter.write_all(output_pcapng, [interface], [packet])

      # Copy to PCAP format should work without crashing (tests get_header tuple unwrapping)
      assert {:ok, 1} = PcapFileEx.copy(output_pcapng, copy_pcap, format: :pcap)

      # Verify copied file is readable
      assert {:ok, copied_packets} = PcapFileEx.read_all(copy_pcap)
      assert length(copied_packets) == 1
      assert hd(copied_packets).data == packet.data
    end

    test "export_filtered/4 works with PCAPNG files" do
      # Same bugs as copy/3, test with export_filtered
      output_pcapng = "/tmp/test_#{:rand.uniform(1_000_000)}.pcapng"
      filtered_pcap = "/tmp/filtered_#{:rand.uniform(1_000_000)}.pcap"

      on_exit(fn ->
        File.rm(output_pcapng)
        File.rm(filtered_pcap)
      end)

      # Create PCAPNG with interface
      interface = %PcapFileEx.Interface{
        id: 0,
        linktype: "ethernet",
        snaplen: 65_535,
        name: "eth0",
        timestamp_resolution: :microsecond,
        timestamp_resolution_raw: "microsecond",
        timestamp_offset_secs: 0
      }

      packets = [
        %PcapFileEx.Packet{
          timestamp: ~U[2025-11-09 10:00:00Z],
          timestamp_precise: %PcapFileEx.Timestamp{secs: 1_731_146_400, nanos: 0},
          orig_len: 100,
          data: <<1, 2, 3, 4, 5>>,
          datalink: "ethernet",
          timestamp_resolution: :microsecond,
          interface_id: 0,
          interface: nil
        },
        %PcapFileEx.Packet{
          timestamp: ~U[2025-11-09 10:00:01Z],
          timestamp_precise: %PcapFileEx.Timestamp{secs: 1_731_146_401, nanos: 0},
          orig_len: 200,
          data: <<6, 7, 8, 9, 10>>,
          datalink: "ethernet",
          timestamp_resolution: :microsecond,
          interface_id: 0,
          interface: nil
        }
      ]

      # Create initial PCAPNG file
      {:ok, _count} = PcapFileEx.PcapNgWriter.write_all(output_pcapng, [interface], packets)

      # Filter to PCAP format should work without crashing
      filter_fun = fn packet -> packet.orig_len > 150 end

      assert {:ok, 1} =
               PcapFileEx.export_filtered(output_pcapng, filtered_pcap, filter_fun, format: :pcap)

      # Verify filtered file contains only large packet
      assert {:ok, filtered_packets} = PcapFileEx.read_all(filtered_pcap)
      assert length(filtered_packets) == 1
      assert hd(filtered_packets).orig_len == 200
    end
  end

  describe "Bug 7: merge/validator error handling" do
    test "validate_datalinks/1 returns error for unreadable files" do
      # Bug: Catch-all clause treated errors as :unknown format
      # Fix: Explicit {:error, reason} handling

      nonexistent_file = "/tmp/nonexistent_#{:rand.uniform(1_000_000)}.pcap"

      # Should return error, not proceed with :unknown format
      assert {:error, reason} = PcapFileEx.Merge.Validator.validate_datalinks([nonexistent_file])
      assert is_binary(reason)

      assert String.contains?(reason, "Cannot detect format") or
               String.contains?(reason, "not found")
    end
  end

  # Note: Bug 8 (merge/stream_merger) is tested indirectly through merge operations
  # The fix ensures Format.detect errors are properly handled with descriptive messages

  describe "Bug 9-10: PCAP→PCAPNG conversion interface_id assignment" do
    test "copy/3 assigns interface_id when converting PCAP to PCAPNG" do
      # Bug: PCAP packets have interface_id == nil, but PCAPNG writer requires valid interface_id
      # Fix: Assign interface_id: 0 when converting from PCAP to PCAPNG

      test_pcap = Path.join([__DIR__, "..", "fixtures", "sample.pcap"])
      output_pcapng = "/tmp/pcap_to_pcapng_#{:rand.uniform(1_000_000)}.pcapng"

      on_exit(fn -> File.rm(output_pcapng) end)

      # Should successfully convert PCAP to PCAPNG
      assert {:ok, count} = PcapFileEx.copy(test_pcap, output_pcapng, format: :pcapng)
      assert count > 0

      # Verify output is valid PCAPNG
      assert PcapFileEx.Format.detect(output_pcapng) == :pcapng

      # Verify packets can be read back
      assert {:ok, packets} = PcapFileEx.read_all(output_pcapng)
      assert length(packets) == count

      # Verify all packets have interface_id assigned
      assert Enum.all?(packets, fn packet ->
               packet.interface_id == 0
             end)
    end

    test "export_filtered/4 assigns interface_id when converting PCAP to PCAPNG" do
      # Same bug as copy/3, test with export_filtered
      test_pcap = Path.join([__DIR__, "..", "fixtures", "sample.pcap"])
      output_pcapng = "/tmp/filtered_to_pcapng_#{:rand.uniform(1_000_000)}.pcapng"

      on_exit(fn -> File.rm(output_pcapng) end)

      # Filter for packets larger than 50 bytes
      filter_fun = fn packet -> byte_size(packet.data) > 50 end

      # Should successfully convert and filter PCAP to PCAPNG
      assert {:ok, count} =
               PcapFileEx.export_filtered(test_pcap, output_pcapng, filter_fun, format: :pcapng)

      assert count > 0

      # Verify output is valid PCAPNG
      assert PcapFileEx.Format.detect(output_pcapng) == :pcapng

      # Verify packets can be read back and match filter
      assert {:ok, packets} = PcapFileEx.read_all(output_pcapng)
      assert length(packets) == count
      assert Enum.all?(packets, filter_fun)

      # Verify all packets have interface_id assigned
      assert Enum.all?(packets, fn packet ->
               packet.interface_id == 0
             end)
    end

    test "round-trip PCAP→PCAPNG→PCAP preserves data" do
      # Regression test for data integrity through format conversion
      test_pcap = Path.join([__DIR__, "..", "fixtures", "sample.pcap"])
      temp_pcapng = "/tmp/roundtrip_#{:rand.uniform(1_000_000)}.pcapng"
      final_pcap = "/tmp/final_#{:rand.uniform(1_000_000)}.pcap"

      on_exit(fn ->
        File.rm(temp_pcapng)
        File.rm(final_pcap)
      end)

      # Read original packets
      {:ok, original_packets} = PcapFileEx.read_all(test_pcap)

      # First conversion: PCAP → PCAPNG
      assert {:ok, count1} = PcapFileEx.copy(test_pcap, temp_pcapng, format: :pcapng)
      assert count1 == length(original_packets)

      # Second conversion: PCAPNG → PCAP
      assert {:ok, count2} = PcapFileEx.copy(temp_pcapng, final_pcap, format: :pcap)
      assert count2 == count1

      # Verify data integrity
      {:ok, final_packets} = PcapFileEx.read_all(final_pcap)
      assert length(final_packets) == length(original_packets)

      Enum.zip(original_packets, final_packets)
      |> Enum.each(fn {orig, final} ->
        assert orig.data == final.data, "Packet data must survive round-trip"
        assert orig.orig_len == final.orig_len, "Original length must be preserved"
      end)
    end
  end
end
