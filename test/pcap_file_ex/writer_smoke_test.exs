defmodule PcapFileEx.WriterSmokeTest do
  use ExUnit.Case, async: true

  @moduletag :writer

  setup do
    # Use a test fixture that exists
    test_file = Path.join([__DIR__, "..", "fixtures", "sample.pcap"])

    # Create temp directory for output files
    temp_dir = System.tmp_dir!()
    test_id = :erlang.unique_integer([:positive])

    output_pcap = Path.join(temp_dir, "test_output_#{test_id}.pcap")
    output_pcapng = Path.join(temp_dir, "test_output_#{test_id}.pcapng")

    on_exit(fn ->
      File.rm(output_pcap)
      File.rm(output_pcapng)
    end)

    {:ok, test_file: test_file, output_pcap: output_pcap, output_pcapng: output_pcapng}
  end

  describe "PcapWriter" do
    test "can write packets to PCAP file", %{test_file: test_file, output_pcap: output_pcap} do
      # Read packets from test file
      {:ok, packets} = PcapFileEx.read_all(test_file)
      refute Enum.empty?(packets), "Test file should have packets"

      # Get header
      {:ok, reader} = PcapFileEx.Pcap.open(test_file)
      header = reader.header

      # Write packets
      {:ok, count} = PcapFileEx.PcapWriter.write_all(output_pcap, header, packets)
      assert count == length(packets), "Should write all packets"

      # Verify file exists and is readable
      assert File.exists?(output_pcap)
      {:ok, read_back_packets} = PcapFileEx.read_all(output_pcap)
      assert length(read_back_packets) == count
    end
  end

  describe "PcapNgWriter" do
    test "can write packets to PCAPNG file", %{
      test_file: test_file,
      output_pcapng: output_pcapng
    } do
      # Read packets from test file
      {:ok, packets} = PcapFileEx.read_all(test_file)
      refute Enum.empty?(packets)

      # Create interface from header
      {:ok, reader} = PcapFileEx.Pcap.open(test_file)
      header = reader.header

      interface = %PcapFileEx.Interface{
        id: 0,
        linktype: header.datalink,
        snaplen: header.snaplen,
        timestamp_resolution: :microsecond,
        timestamp_resolution_raw: "microsecond",
        timestamp_offset_secs: 0
      }

      # Set interface_id on packets
      packets_with_interface = Enum.map(packets, &%{&1 | interface_id: 0})

      # Write packets
      result =
        PcapFileEx.PcapNgWriter.write_all(output_pcapng, [interface], packets_with_interface)

      assert {:ok, count} = result, "write_all failed: #{inspect(result)}"
      assert count == length(packets)

      # Verify file exists and has content
      assert File.exists?(output_pcapng)
      file_size = File.stat!(output_pcapng).size
      assert file_size > 0, "File is empty (#{file_size} bytes)"

      {:ok, read_back_packets} = PcapFileEx.read_all(output_pcapng)
      assert length(read_back_packets) == count
    end
  end

  describe "High-level API" do
    test "copy() works for PCAP files", %{test_file: test_file, output_pcap: output_pcap} do
      {:ok, count} = PcapFileEx.copy(test_file, output_pcap)
      assert count > 0

      # Verify
      {:ok, original} = PcapFileEx.read_all(test_file)
      {:ok, copied} = PcapFileEx.read_all(output_pcap)
      assert length(original) == length(copied)
    end

    test "export_filtered() works", %{test_file: test_file, output_pcap: output_pcap} do
      # Filter for packets larger than 100 bytes
      filter_fun = fn packet -> byte_size(packet.data) > 100 end

      {:ok, count} = PcapFileEx.export_filtered(test_file, output_pcap, filter_fun)
      assert count > 0

      # Verify all exported packets match filter
      {:ok, exported} = PcapFileEx.read_all(output_pcap)
      assert Enum.all?(exported, filter_fun)
    end

    test "copy() can convert PCAP to PCAPNG", %{
      test_file: test_file,
      output_pcapng: output_pcapng
    } do
      # Copy PCAP to PCAPNG format
      {:ok, count} = PcapFileEx.copy(test_file, output_pcapng, format: :pcapng)
      assert count > 0

      # Verify file exists and is valid PCAPNG
      assert File.exists?(output_pcapng)
      assert PcapFileEx.Format.detect(output_pcapng) == :pcapng

      # Verify all packets were copied
      {:ok, original} = PcapFileEx.read_all(test_file)
      {:ok, converted} = PcapFileEx.read_all(output_pcapng)
      assert length(original) == length(converted)

      # Verify packet data is preserved
      Enum.zip(original, converted)
      |> Enum.each(fn {orig, conv} ->
        assert orig.data == conv.data, "Packet data should be identical"
        assert orig.orig_len == conv.orig_len, "Original length should be preserved"
      end)
    end

    test "export_filtered() can convert PCAP to PCAPNG", %{
      test_file: test_file,
      output_pcapng: output_pcapng
    } do
      # Filter for packets larger than 50 bytes
      filter_fun = fn packet -> byte_size(packet.data) > 50 end

      # Export with PCAPNG format
      {:ok, count} =
        PcapFileEx.export_filtered(test_file, output_pcapng, filter_fun, format: :pcapng)

      assert count > 0

      # Verify file is valid PCAPNG
      assert File.exists?(output_pcapng)
      assert PcapFileEx.Format.detect(output_pcapng) == :pcapng

      # Verify all exported packets match filter
      {:ok, exported} = PcapFileEx.read_all(output_pcapng)
      assert length(exported) == count
      assert Enum.all?(exported, filter_fun)
    end

    test "round-trip PCAP→PCAPNG→PCAP preserves data", %{
      test_file: test_file,
      output_pcap: output_pcap,
      output_pcapng: output_pcapng
    } do
      # First: PCAP → PCAPNG
      {:ok, count1} = PcapFileEx.copy(test_file, output_pcapng, format: :pcapng)
      assert count1 > 0

      # Second: PCAPNG → PCAP
      {:ok, count2} = PcapFileEx.copy(output_pcapng, output_pcap, format: :pcap)
      assert count2 == count1, "Packet count should remain the same"

      # Verify data integrity through round-trip
      {:ok, original} = PcapFileEx.read_all(test_file)
      {:ok, final} = PcapFileEx.read_all(output_pcap)

      assert length(original) == length(final), "Packet count should be preserved"

      Enum.zip(original, final)
      |> Enum.each(fn {orig, final_pkt} ->
        assert orig.data == final_pkt.data, "Packet data must survive round-trip"
        assert orig.orig_len == final_pkt.orig_len, "Original length must be preserved"
      end)
    end
  end

  describe "Append mode limitations" do
    test "PCAP append returns error", %{output_pcap: output_pcap} do
      # Create a file first
      header = %PcapFileEx.Header{
        version_major: 2,
        version_minor: 4,
        snaplen: 65_535,
        datalink: "ethernet",
        ts_resolution: "microsecond",
        endianness: "little"
      }

      {:ok, 0} = PcapFileEx.PcapWriter.write_all(output_pcap, header, [])

      # Try to append - should fail with clear error
      assert {:error, reason} = PcapFileEx.PcapWriter.append(output_pcap)
      assert reason =~ "not supported"
    end

    test "PCAPNG append returns error", %{output_pcapng: output_pcapng} do
      # Create a file first
      {:ok, writer} = PcapFileEx.PcapNgWriter.open(output_pcapng)
      :ok = PcapFileEx.PcapNgWriter.close(writer)

      # Try to append - should fail with clear error
      assert {:error, reason} = PcapFileEx.PcapNgWriter.append(output_pcapng)
      assert reason =~ "not yet implemented"
    end
  end
end
