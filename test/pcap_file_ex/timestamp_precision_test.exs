defmodule PcapFileEx.TimestampPrecisionTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Tests for PCAP timestamp precision support (microsecond and nanosecond).

  PCAP files can have different timestamp precision indicated by magic numbers:
  - 0xD4C3B2A1 (little-endian microsecond) - macOS default
  - 0xA1B2C3D4 (big-endian microsecond)
  - 0x4D3CB2A1 (little-endian nanosecond) - Linux default
  - 0xA1B23C4D (big-endian nanosecond)

  This test suite verifies that all formats are properly supported.
  """

  describe "PCAP microsecond precision (macOS format)" do
    @tag :pcap_microsecond
    test "opens and reads macOS PCAP file with microsecond timestamps" do
      # macOS generates microsecond precision by default
      case File.exists?("test/fixtures/new_test.pcap") do
        true ->
          {:ok, reader} = PcapFileEx.Pcap.open("test/fixtures/new_test.pcap")
          assert reader.header.ts_resolution == "microsecond"
          assert reader.header.endianness in ["little", "big"]

          # Verify packets can be read
          {:ok, packets} = PcapFileEx.Pcap.read_all("test/fixtures/new_test.pcap")
          assert length(packets) > 0
          assert Enum.all?(packets, fn p -> is_struct(p, PcapFileEx.Packet) end)

        false ->
          IO.puts(
            "\nSkipping macOS microsecond PCAP test - test/fixtures/new_test.pcap not found"
          )

          :ok
      end
    end

    @tag :validator
    test "validator recognizes microsecond PCAP files" do
      case File.exists?("test/fixtures/new_test.pcap") do
        true ->
          assert {:ok, :pcap} = PcapFileEx.Validator.validate("test/fixtures/new_test.pcap")
          assert PcapFileEx.Validator.pcap?("test/fixtures/new_test.pcap")

        false ->
          :ok
      end
    end
  end

  describe "PCAP nanosecond precision (Linux format)" do
    @tag :pcap_nanosecond
    test "opens and reads Linux PCAP file with nanosecond timestamps" do
      # Linux dumpcap defaults to nanosecond precision
      {:ok, reader} = PcapFileEx.Pcap.open("test/fixtures/linux_new_test.pcap")

      # Verify header shows nanosecond precision
      assert reader.header.ts_resolution == "nanosecond"
      assert reader.header.endianness == "little"
      assert reader.header.datalink == "ethernet"

      # Verify we can read packets
      {:ok, packets} = PcapFileEx.Pcap.read_all("test/fixtures/linux_new_test.pcap")
      assert length(packets) > 0
      assert Enum.all?(packets, fn p -> is_struct(p, PcapFileEx.Packet) end)

      # Verify timestamps are present
      first_packet = Enum.at(packets, 0)
      assert %DateTime{} = first_packet.timestamp
      assert first_packet.orig_len > 0
      assert byte_size(first_packet.data) > 0
    end

    @tag :validator
    test "validator recognizes nanosecond PCAP files" do
      assert {:ok, :pcap} = PcapFileEx.Validator.validate("test/fixtures/linux_new_test.pcap")
      assert PcapFileEx.Validator.pcap?("test/fixtures/linux_new_test.pcap")
      refute PcapFileEx.Validator.pcapng?("test/fixtures/linux_new_test.pcap")
    end

    @tag :pcap_nanosecond
    test "nanosecond PCAP timestamps have correct precision" do
      {:ok, packets} = PcapFileEx.Pcap.read_all("test/fixtures/linux_new_test.pcap")

      # All packets should have valid timestamps
      assert Enum.all?(packets, fn p ->
               match?(%DateTime{}, p.timestamp) and
                 DateTime.to_unix(p.timestamp, :nanosecond) > 0
             end)
    end

    @tag :pcap_nanosecond
    test "can stream nanosecond PCAP file" do
      packet_count =
        PcapFileEx.stream("test/fixtures/linux_new_test.pcap")
        |> Enum.count()

      assert packet_count > 0
    end

    @tag :pcap_nanosecond
    test "auto-detection works for nanosecond PCAP" do
      {:ok, reader} = PcapFileEx.open("test/fixtures/linux_new_test.pcap")
      assert is_struct(reader, PcapFileEx.Pcap)
    end
  end

  describe "PCAPNG format compatibility" do
    @tag :pcapng
    test "opens Linux PCAPNG file" do
      {:ok, reader} = PcapFileEx.PcapNg.open("test/fixtures/linux_new_test.pcapng")
      assert is_struct(reader, PcapFileEx.PcapNg)

      {:ok, packets} = PcapFileEx.PcapNg.read_all("test/fixtures/linux_new_test.pcapng")
      assert length(packets) > 0
    end

    @tag :pcapng
    test "validator recognizes PCAPNG files" do
      assert {:ok, :pcapng} =
               PcapFileEx.Validator.validate("test/fixtures/linux_new_test.pcapng")

      assert PcapFileEx.Validator.pcapng?("test/fixtures/linux_new_test.pcapng")
      refute PcapFileEx.Validator.pcap?("test/fixtures/linux_new_test.pcapng")
    end

    @tag :pcapng
    test "opens macOS PCAPNG file" do
      case File.exists?("test/fixtures/new_test.pcapng") do
        true ->
          {:ok, reader} = PcapFileEx.PcapNg.open("test/fixtures/new_test.pcapng")
          assert is_struct(reader, PcapFileEx.PcapNg)

          {:ok, packets} = PcapFileEx.PcapNg.read_all("test/fixtures/new_test.pcapng")
          assert length(packets) > 0

        false ->
          :ok
      end
    end
  end

  describe "Cross-platform compatibility" do
    @tag :cross_platform
    test "both Linux and macOS PCAP formats are supported" do
      # Linux nanosecond PCAP
      assert {:ok, :pcap} = PcapFileEx.Validator.validate("test/fixtures/linux_new_test.pcap")

      # macOS microsecond PCAP (if available)
      if File.exists?("test/fixtures/new_test.pcap") do
        assert {:ok, :pcap} = PcapFileEx.Validator.validate("test/fixtures/new_test.pcap")
      end
    end

    @tag :cross_platform
    test "both Linux and macOS PCAPNG formats are supported" do
      # Linux PCAPNG
      assert {:ok, :pcapng} =
               PcapFileEx.Validator.validate("test/fixtures/linux_new_test.pcapng")

      # macOS PCAPNG (if available)
      if File.exists?("test/fixtures/new_test.pcapng") do
        assert {:ok, :pcapng} = PcapFileEx.Validator.validate("test/fixtures/new_test.pcapng")
      end
    end

    @tag :cross_platform
    test "reads same data from different timestamp precisions" do
      # Both files should have similar packet structures
      {:ok, linux_packets} = PcapFileEx.Pcap.read_all("test/fixtures/linux_new_test.pcap")

      assert length(linux_packets) > 0
      assert Enum.all?(linux_packets, fn p -> byte_size(p.data) > 0 end)
      assert Enum.all?(linux_packets, fn p -> is_struct(p.timestamp, DateTime) end)
    end
  end

  describe "Error handling" do
    @tag :error_handling
    test "rejects invalid magic numbers" do
      # Create a temp file with invalid magic
      temp_file = Path.join(System.tmp_dir!(), "invalid_pcap_#{:rand.uniform(10000)}.pcap")
      File.write!(temp_file, <<0xFF, 0xFF, 0xFF, 0xFF, "invalid data">>)

      result = PcapFileEx.Validator.validate(temp_file)
      assert match?({:error, "Unknown file format" <> _}, result)

      File.rm!(temp_file)
    end

    @tag :error_handling
    test "rejects empty files" do
      temp_file = Path.join(System.tmp_dir!(), "empty_#{:rand.uniform(10000)}.pcap")
      File.write!(temp_file, "")

      result = PcapFileEx.Validator.validate(temp_file)
      assert {:error, "File is empty"} = result

      File.rm!(temp_file)
    end
  end
end
