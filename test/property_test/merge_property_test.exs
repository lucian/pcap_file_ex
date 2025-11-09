defmodule PcapFileEx.MergePropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias PcapFileEx.{Merge, Timestamp}

  # Use existing test fixtures for property tests
  @sample_pcap "test/fixtures/sample.pcap"
  @sample_pcapng "test/fixtures/sample.pcapng"

  property "merged stream maintains chronological ordering" do
    check all(
            # Use existing files repeatedly to test ordering
            files <-
              StreamData.member_of([
                [@sample_pcap, @sample_pcap],
                [@sample_pcapng, @sample_pcapng],
                [@sample_pcap, @sample_pcapng]
              ])
          ) do
      {:ok, stream} = Merge.stream(files)

      packets =
        stream
        |> Enum.to_list()

      # Check chronological ordering
      packets
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.each(fn [p1, p2] ->
        assert Timestamp.compare(p1.timestamp_precise, p2.timestamp_precise) in [:lt, :eq],
               "Packets not in chronological order"
      end)
    end
  end

  property "merge preserves total packet count" do
    check all(
            files <-
              StreamData.member_of([
                [@sample_pcap, @sample_pcap],
                [@sample_pcapng, @sample_pcapng],
                [@sample_pcap, @sample_pcapng]
              ])
          ) do
      # Get individual counts
      individual_counts =
        files
        |> Enum.map(fn file ->
          {:ok, stream} = PcapFileEx.stream(file)

          Enum.count(stream, fn
            {:ok, _} -> true
            _ -> false
          end)
        end)

      total_expected = Enum.sum(individual_counts)

      # Get merged count
      {:ok, merged_stream} = Merge.stream(files)
      merged_count = Enum.count(merged_stream)

      assert merged_count == total_expected,
             "Merged count #{merged_count} != expected #{total_expected}"
    end
  end

  property "annotation includes source file metadata" do
    check all(
            files <-
              StreamData.member_of([
                [@sample_pcap, @sample_pcap],
                [@sample_pcapng, @sample_pcapng]
              ])
          ) do
      {:ok, stream} = Merge.stream(files, annotate_source: true)

      stream
      |> Enum.take(10)
      |> Enum.each(fn {_packet, metadata} ->
        assert is_map(metadata)
        assert Map.has_key?(metadata, :source_file)
        assert Map.has_key?(metadata, :file_index)
        assert Map.has_key?(metadata, :packet_index)
        assert metadata.source_file in files
        assert is_integer(metadata.file_index)
        assert is_integer(metadata.packet_index)
      end)
    end
  end

  property "deterministic ordering for identical timestamps" do
    check all(
            files <-
              StreamData.member_of([
                [@sample_pcap, @sample_pcap],
                [@sample_pcapng, @sample_pcapng]
              ])
          ) do
      # Run merge twice, should get same order
      {:ok, stream1} = Merge.stream(files, annotate_source: true)
      {:ok, stream2} = Merge.stream(files, annotate_source: true)

      packets1 =
        stream1
        |> Enum.map(fn {packet, meta} ->
          {packet.timestamp_precise, meta.file_index, meta.packet_index}
        end)
        |> Enum.to_list()

      packets2 =
        stream2
        |> Enum.map(fn {packet, meta} ->
          {packet.timestamp_precise, meta.file_index, meta.packet_index}
        end)
        |> Enum.to_list()

      assert packets1 == packets2,
             "Merge order is not deterministic"
    end
  end

  property ":collect mode wraps items in result tuples" do
    check all(
            files <-
              StreamData.member_of([
                [@sample_pcap],
                [@sample_pcapng]
              ])
          ) do
      {:ok, stream} = Merge.stream(files, on_error: :collect)

      stream
      |> Enum.take(5)
      |> Enum.each(fn item ->
        assert match?({:ok, _}, item),
               "Expected {:ok, packet}, got #{inspect(item)}"
      end)
    end
  end

  property ":collect mode with annotation creates nested tuples" do
    check all(
            files <-
              StreamData.member_of([
                [@sample_pcap],
                [@sample_pcapng]
              ])
          ) do
      {:ok, stream} = Merge.stream(files, annotate_source: true, on_error: :collect)

      stream
      |> Enum.take(5)
      |> Enum.each(fn item ->
        assert match?({:ok, {_packet, _meta}}, item),
               "Expected {:ok, {packet, meta}}, got #{inspect(item)}"

        {:ok, {_packet, meta}} = item
        assert is_map(meta)
        assert Map.has_key?(meta, :source_file)
      end)
    end
  end

  property "count/1 returns total packet count" do
    check all(
            files <-
              StreamData.member_of([
                [@sample_pcap, @sample_pcap],
                [@sample_pcapng, @sample_pcapng],
                [@sample_pcap, @sample_pcapng]
              ])
          ) do
      total_count = Merge.count(files)

      {:ok, stream} = Merge.stream(files)
      stream_count = Enum.count(stream)

      assert total_count == stream_count,
             "count/1 returned #{total_count} but stream has #{stream_count} packets"
    end
  end

  property "validate_clocks/1 returns stats for valid files" do
    check all(
            files <-
              StreamData.member_of([
                [@sample_pcap],
                [@sample_pcapng],
                [@sample_pcap, @sample_pcapng]
              ])
          ) do
      case Merge.validate_clocks(files) do
        {:ok, stats} ->
          assert is_map(stats)
          assert Map.has_key?(stats, :max_drift_ms)
          assert Map.has_key?(stats, :files)
          assert is_float(stats.max_drift_ms)
          assert is_list(stats.files)

        {:error, :excessive_drift, stats} ->
          # Acceptable if drift is high
          assert is_map(stats)
          assert Map.has_key?(stats, :max_drift_ms)
      end
    end
  end

  property "stream!/2 raises on invalid inputs" do
    check all(
            invalid_input <-
              StreamData.member_of([
                [],
                ["nonexistent.pcap"],
                ["nonexistent1.pcap", "nonexistent2.pcap"]
              ])
          ) do
      assert_raise ArgumentError, fn ->
        Merge.stream!(invalid_input)
      end
    end
  end

  property "empty file list returns error" do
    check all(_ <- StreamData.constant(nil)) do
      assert {:error, :empty_paths} = Merge.stream([])
      assert Merge.count([]) == 0

      {:ok, stats} = Merge.validate_clocks([])
      assert stats.max_drift_ms == 0.0
      assert stats.files == []
    end
  end

  property "PCAPNG interface remapping maintains invariant" do
    check all(
            files <-
              StreamData.member_of([
                [@sample_pcapng, @sample_pcapng]
              ])
          ) do
      {:ok, stream} = Merge.stream(files)

      # Check invariant: packet.interface_id == packet.interface.id for all PCAPNG packets
      stream
      |> Enum.take(20)
      |> Enum.filter(fn packet -> packet.interface != nil end)
      |> Enum.each(fn packet ->
        assert packet.interface_id == packet.interface.id,
               "Invariant broken: interface_id=#{packet.interface_id}, interface.id=#{packet.interface.id}"
      end)
    end
  end

  property "PCAPNG annotation includes both interface IDs" do
    check all(
            files <-
              StreamData.member_of([
                [@sample_pcapng, @sample_pcapng]
              ])
          ) do
      {:ok, stream} = Merge.stream(files, annotate_source: true)

      stream
      |> Enum.take(10)
      |> Enum.each(fn {packet, metadata} ->
        # PCAPNG packets should have both original and remapped interface IDs
        assert Map.has_key?(metadata, :original_interface_id),
               "Missing original_interface_id in metadata"

        assert Map.has_key?(metadata, :remapped_interface_id),
               "Missing remapped_interface_id in metadata"

        # Remapped ID should match packet.interface_id
        assert metadata.remapped_interface_id == packet.interface_id,
               "remapped_interface_id doesn't match packet.interface_id"
      end)
    end
  end
end
