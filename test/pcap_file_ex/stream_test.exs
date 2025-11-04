defmodule PcapFileEx.StreamTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.{Pcap, PcapNg, PreFilter, Stream}

  @pcap_fixture "test/fixtures/sample.pcap"
  @pcapng_fixture "test/fixtures/sample.pcapng"

  describe "from_reader/1 with Pcap" do
    test "streams packets from Pcap reader" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      packets = Stream.from_reader(reader) |> Enum.to_list()

      assert length(packets) > 0
      assert Enum.all?(packets, &is_struct(&1, PcapFileEx.Packet))

      Pcap.close(reader)
    end

    test "works with pre-filters on Pcap reader" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      filters = [PreFilter.protocol("tcp")]
      :ok = Pcap.set_filter(reader, filters)

      packets = Stream.from_reader(reader) |> Enum.to_list()

      # All packets should be TCP
      for packet <- packets do
        assert :tcp in packet.protocols
      end

      Pcap.close(reader)
    end
  end

  describe "from_reader/1 with PcapNg" do
    test "streams packets from PcapNg reader" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      packets = Stream.from_reader(reader) |> Enum.to_list()

      assert length(packets) > 0
      assert Enum.all?(packets, &is_struct(&1, PcapFileEx.Packet))

      PcapNg.close(reader)
    end

    test "works with pre-filters on PcapNg reader" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      filters = [PreFilter.protocol("tcp")]
      :ok = PcapNg.set_filter(reader, filters)

      packets = Stream.from_reader(reader) |> Enum.to_list()

      # All packets should be TCP
      for packet <- packets do
        assert :tcp in packet.protocols
      end

      PcapNg.close(reader)
    end

    test "handles combined filters on PcapNg reader" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      filters = [
        PreFilter.protocol("tcp"),
        PreFilter.size_min(50)
      ]

      :ok = PcapNg.set_filter(reader, filters)

      packets = Stream.from_reader(reader) |> Enum.to_list()

      # All packets should be TCP and >= 50 bytes
      for packet <- packets do
        assert :tcp in packet.protocols
        assert packet.orig_len >= 50
      end

      PcapNg.close(reader)
    end
  end

  describe "from_reader/1 with Elixir Stream operations" do
    test "can be used with Elixir Stream.take on Pcap" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      packets =
        PcapFileEx.Stream.from_reader(reader)
        |> Elixir.Stream.take(5)
        |> Enum.to_list()

      assert length(packets) == 5

      Pcap.close(reader)
    end

    test "can be used with Elixir Stream.take on PcapNg" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      packets =
        PcapFileEx.Stream.from_reader(reader)
        |> Elixir.Stream.take(5)
        |> Enum.to_list()

      assert length(packets) == 5

      PcapNg.close(reader)
    end

    test "can be filtered and mapped on PcapNg" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      sizes =
        PcapFileEx.Stream.from_reader(reader)
        |> Elixir.Stream.map(fn packet -> packet.orig_len end)
        |> Elixir.Stream.filter(fn size -> size > 100 end)
        |> Enum.take(3)

      assert length(sizes) <= 3
      assert Enum.all?(sizes, &(&1 > 100))

      PcapNg.close(reader)
    end
  end
end
