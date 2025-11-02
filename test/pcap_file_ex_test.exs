defmodule PcapFileExTest do
  use ExUnit.Case, async: true
  doctest PcapFileEx

  alias PcapFileEx

  @test_pcap_file "test/fixtures/sample.pcap"

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
end
