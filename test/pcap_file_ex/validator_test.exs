defmodule PcapFileEx.ValidatorTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.Validator

  @test_pcap_file "test/fixtures/sample.pcap"
  @test_pcapng_file "test/fixtures/sample.pcapng"

  describe "validate/1" do
    test "validates PCAP file" do
      assert {:ok, :pcap} = Validator.validate(@test_pcap_file)
    end

    test "validates PCAPNG file" do
      assert {:ok, :pcapng} = Validator.validate(@test_pcapng_file)
    end

    test "returns error for non-existent file" do
      assert {:error, _reason} = Validator.validate("nonexistent.pcap")
    end

    test "returns error for invalid file" do
      invalid_file = "test/fixtures/invalid_test.pcap"
      File.write!(invalid_file, "not a pcap file")

      assert {:error, reason} = Validator.validate(invalid_file)
      assert reason =~ "Unknown file format"

      File.rm!(invalid_file)
    end
  end

  describe "pcap?/1" do
    test "returns true for PCAP file" do
      assert Validator.pcap?(@test_pcap_file) == true
    end

    test "returns false for PCAPNG file" do
      assert Validator.pcap?(@test_pcapng_file) == false
    end

    test "returns false for non-existent file" do
      assert Validator.pcap?("nonexistent.pcap") == false
    end
  end

  describe "pcapng?/1" do
    test "returns true for PCAPNG file" do
      assert Validator.pcapng?(@test_pcapng_file) == true
    end

    test "returns false for PCAP file" do
      assert Validator.pcapng?(@test_pcap_file) == false
    end

    test "returns false for non-existent file" do
      assert Validator.pcapng?("nonexistent.pcapng") == false
    end
  end

  describe "readable?/1" do
    test "returns true for readable file" do
      assert Validator.readable?(@test_pcap_file) == true
    end

    test "returns false for non-existent file" do
      assert Validator.readable?("nonexistent.pcap") == false
    end
  end

  describe "file_size/1" do
    test "returns file size for existing file" do
      assert {:ok, size} = Validator.file_size(@test_pcap_file)
      assert is_integer(size)
      assert size > 0
    end

    test "returns error for non-existent file" do
      assert {:error, :enoent} = Validator.file_size("nonexistent.pcap")
    end
  end
end
