defmodule PcapFileEx.StreamTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.{Pcap, PcapNg, PreFilter, Stream}

  @pcap_fixture "test/fixtures/sample.pcap"
  @pcapng_fixture "test/fixtures/sample.pcapng"
  @corrupted_fixture "test/fixtures/corrupted.pcap"

  describe "from_reader!/1 with Pcap" do
    test "streams packets from Pcap reader" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      packets = Stream.from_reader!(reader) |> Enum.to_list()

      assert length(packets) > 0
      assert Enum.all?(packets, &is_struct(&1, PcapFileEx.Packet))

      Pcap.close(reader)
    end

    test "works with pre-filters on Pcap reader" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      filters = [PreFilter.protocol("tcp")]
      :ok = Pcap.set_filter(reader, filters)

      packets = Stream.from_reader!(reader) |> Enum.to_list()

      # All packets should be TCP
      for packet <- packets do
        assert :tcp in packet.protocols
      end

      Pcap.close(reader)
    end
  end

  describe "from_reader!/1 with PcapNg" do
    test "streams packets from PcapNg reader" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      packets = Stream.from_reader!(reader) |> Enum.to_list()

      assert length(packets) > 0
      assert Enum.all?(packets, &is_struct(&1, PcapFileEx.Packet))

      PcapNg.close(reader)
    end

    test "works with pre-filters on PcapNg reader" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      filters = [PreFilter.protocol("tcp")]
      :ok = PcapNg.set_filter(reader, filters)

      packets = Stream.from_reader!(reader) |> Enum.to_list()

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

      packets = Stream.from_reader!(reader) |> Enum.to_list()

      # All packets should be TCP and >= 50 bytes
      for packet <- packets do
        assert :tcp in packet.protocols
        assert packet.orig_len >= 50
      end

      PcapNg.close(reader)
    end
  end

  describe "from_reader!/1 with Elixir Stream operations" do
    test "can be used with Elixir Stream.take on Pcap" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      packets =
        PcapFileEx.Stream.from_reader!(reader)
        |> Elixir.Stream.take(5)
        |> Enum.to_list()

      assert length(packets) == 5

      Pcap.close(reader)
    end

    test "can be used with Elixir Stream.take on PcapNg" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      packets =
        PcapFileEx.Stream.from_reader!(reader)
        |> Elixir.Stream.take(5)
        |> Enum.to_list()

      assert length(packets) == 5

      PcapNg.close(reader)
    end

    test "can be filtered and mapped on PcapNg" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      sizes =
        PcapFileEx.Stream.from_reader!(reader)
        |> Elixir.Stream.map(fn packet -> packet.orig_len end)
        |> Elixir.Stream.filter(fn size -> size > 100 end)
        |> Enum.take(3)

      assert length(sizes) <= 3
      assert Enum.all?(sizes, &(&1 > 100))

      PcapNg.close(reader)
    end
  end

  describe "packets/1 safe variant" do
    test "returns {:ok, stream} for valid file" do
      assert {:ok, stream} = Stream.packets(@pcap_fixture)
      # Verify we can use the stream by taking one item
      assert [{:ok, _packet}] = Enum.take(stream, 1)
    end

    test "returns {:error, reason} for nonexistent file" do
      assert {:error, reason} = Stream.packets("nonexistent.pcap")
      assert is_binary(reason)
    end

    test "emits {:ok, packet} tuples for valid packets" do
      {:ok, stream} = Stream.packets(@pcap_fixture)

      items = Enum.take(stream, 3)

      assert length(items) == 3

      assert Enum.all?(items, fn
               {:ok, packet} -> is_struct(packet, PcapFileEx.Packet)
               _ -> false
             end)
    end

    test "all valid packets are wrapped in {:ok, _} tuples" do
      {:ok, stream} = Stream.packets(@pcap_fixture)

      all_ok? =
        Enum.all?(stream, fn
          {:ok, _packet} -> true
          {:error, _meta} -> false
        end)

      assert all_ok?, "Expected all items to be {:ok, packet} tuples"
    end

    test "can extract packets with pattern matching" do
      {:ok, stream} = Stream.packets(@pcap_fixture)

      packets =
        stream
        |> Enum.map(fn {:ok, packet} -> packet end)
        |> Enum.take(5)

      assert length(packets) == 5
      assert Enum.all?(packets, &is_struct(&1, PcapFileEx.Packet))
    end

    test "works with Stream.filter to handle errors" do
      {:ok, stream} = Stream.packets(@pcap_fixture)

      packets =
        stream
        |> Elixir.Stream.filter(fn
          {:ok, _} -> true
          {:error, _} -> false
        end)
        |> Elixir.Stream.map(fn {:ok, packet} -> packet end)
        |> Enum.take(5)

      assert length(packets) == 5
    end

    test "works with Enum.reduce_while to stop on error" do
      {:ok, stream} = Stream.packets(@pcap_fixture)

      result =
        Enum.reduce_while(stream, [], fn
          {:ok, packet}, acc -> {:cont, [packet | acc]}
          {:error, meta}, _acc -> {:halt, {:error, meta}}
        end)

      assert is_list(result)
      assert length(result) > 0
    end
  end

  describe "packets/1 with corrupted file" do
    test "emits {:error, metadata} for corrupted packets" do
      {:ok, stream} = Stream.packets(@corrupted_fixture)

      # Consume stream and collect results
      items = Enum.to_list(stream)

      # Should have some successful packets before the error
      ok_count =
        Enum.count(items, fn
          {:ok, _} -> true
          _ -> false
        end)

      error_count =
        Enum.count(items, fn
          {:error, _} -> true
          _ -> false
        end)

      # We expect at least one error due to corruption
      assert error_count > 0, "Expected at least one error tuple from corrupted file"
      # We may have some successful packets before the error
      assert ok_count >= 0
    end

    test "error metadata includes reason and packet_index" do
      {:ok, stream} = Stream.packets(@corrupted_fixture)

      error_tuple =
        Enum.find(stream, fn
          {:error, _} -> true
          _ -> false
        end)

      if error_tuple do
        {:error, meta} = error_tuple
        assert is_map(meta)
        assert Map.has_key?(meta, :reason)
        assert Map.has_key?(meta, :packet_index)
        assert is_binary(meta.reason)
        assert is_integer(meta.packet_index)
        assert meta.packet_index >= 0
      end
    end

    test "stream halts after emitting error" do
      {:ok, stream} = Stream.packets(@corrupted_fixture)

      items = Enum.to_list(stream)

      # Find the position of the first error
      error_index =
        Enum.find_index(items, fn
          {:error, _} -> true
          _ -> false
        end)

      if error_index do
        # Everything after the error should not exist (stream halted)
        assert error_index == length(items) - 1,
               "Expected stream to halt after error, but found #{length(items) - error_index - 1} items after error"
      end
    end

    test "can collect packets before error" do
      {:ok, stream} = Stream.packets(@corrupted_fixture)

      {packets, errors} =
        Enum.reduce(stream, {[], []}, fn
          {:ok, packet}, {pkts, errs} -> {[packet | pkts], errs}
          {:error, meta}, {pkts, errs} -> {pkts, [meta | errs]}
        end)

      # We should have collected some valid packets
      assert length(packets) >= 0
      # And at least one error
      assert length(errors) > 0
    end
  end

  describe "from_reader/1 safe variant with Pcap" do
    test "emits {:ok, packet} tuples for valid packets" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      stream = Stream.from_reader(reader)
      items = Enum.take(stream, 3)

      assert length(items) == 3

      assert Enum.all?(items, fn
               {:ok, packet} -> is_struct(packet, PcapFileEx.Packet)
               _ -> false
             end)

      Pcap.close(reader)
    end

    test "can be filtered and mapped" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      packets =
        Stream.from_reader(reader)
        |> Elixir.Stream.filter(fn
          {:ok, _} -> true
          {:error, _} -> false
        end)
        |> Elixir.Stream.map(fn {:ok, packet} -> packet end)
        |> Enum.take(5)

      assert length(packets) == 5
      assert Enum.all?(packets, &is_struct(&1, PcapFileEx.Packet))

      Pcap.close(reader)
    end

    test "works with corrupted file" do
      {:ok, reader} = Pcap.open(@corrupted_fixture)

      items = Stream.from_reader(reader) |> Enum.to_list()

      # Check we have both ok and error tuples
      has_error =
        Enum.any?(items, fn
          {:error, _} -> true
          _ -> false
        end)

      assert has_error, "Expected at least one error from corrupted file"

      Pcap.close(reader)
    end
  end

  describe "from_reader/1 safe variant with PcapNg" do
    test "emits {:ok, packet} tuples for valid packets" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      stream = Stream.from_reader(reader)
      items = Enum.take(stream, 3)

      assert length(items) == 3

      assert Enum.all?(items, fn
               {:ok, packet} -> is_struct(packet, PcapFileEx.Packet)
               _ -> false
             end)

      PcapNg.close(reader)
    end

    test "can be filtered and mapped" do
      {:ok, reader} = PcapNg.open(@pcapng_fixture)

      packets =
        Stream.from_reader(reader)
        |> Elixir.Stream.filter(fn
          {:ok, _} -> true
          {:error, _} -> false
        end)
        |> Elixir.Stream.map(fn {:ok, packet} -> packet end)
        |> Enum.take(5)

      assert length(packets) == 5
      assert Enum.all?(packets, &is_struct(&1, PcapFileEx.Packet))

      PcapNg.close(reader)
    end
  end

  describe "packets!/1 backward compatibility" do
    test "still raises on mid-stream errors with corrupted file" do
      stream = Stream.packets!(@corrupted_fixture)

      # This should raise when we try to enumerate the corrupted packets
      assert_raise RuntimeError, ~r/Failed to read packet/, fn ->
        Enum.to_list(stream)
      end
    end

    test "still works normally with valid files" do
      stream = Stream.packets!(@pcap_fixture)
      packets = Enum.to_list(stream)

      assert length(packets) > 0
      assert Enum.all?(packets, &is_struct(&1, PcapFileEx.Packet))
    end
  end

  describe "from_reader!/1 backward compatibility" do
    test "still raises on mid-stream errors with corrupted Pcap" do
      {:ok, reader} = Pcap.open(@corrupted_fixture)

      stream = Stream.from_reader!(reader)

      assert_raise RuntimeError, ~r/Failed to read packet/, fn ->
        Enum.to_list(stream)
      end

      Pcap.close(reader)
    end

    test "still works normally with valid Pcap files" do
      {:ok, reader} = Pcap.open(@pcap_fixture)

      packets = Stream.from_reader!(reader) |> Enum.to_list()

      assert length(packets) > 0
      assert Enum.all?(packets, &is_struct(&1, PcapFileEx.Packet))

      Pcap.close(reader)
    end
  end
end
