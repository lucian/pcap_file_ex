Mix.Task.run("app.start")

alias PcapFileEx.{Filter, HTTP, Packet, Pcap, PcapNg, PreFilter}

defmodule PcapFileExBench do
  @moduledoc false

  def run(path) do
    Benchee.run(
      %{
        # Baseline benchmarks
        "stream parse (decode: false)" => fn -> parse_raw(path) end,
        "stream parse (decode: true)" => fn -> parse_decoded(path) end,

        # Post-filtering benchmarks (Elixir layer)
        "POST-FILTER: UDP packets" => fn -> filter_udp(path) end,
        "POST-FILTER: TCP packets" => fn -> filter_tcp(path) end,
        "POST-FILTER: HTTP POST requests" => fn -> filter_http_post(path) end,
        "POST-FILTER: large packets (>1000 bytes)" => fn -> filter_large_packets(path) end,

        # Pre-filtering benchmarks (Rust layer)
        "PRE-FILTER: UDP packets" => fn -> prefilter_udp(path) end,
        "PRE-FILTER: TCP packets" => fn -> prefilter_tcp(path) end,
        "PRE-FILTER: TCP port 80" => fn -> prefilter_tcp_port_80(path) end,
        "PRE-FILTER: TCP port 80 or 443" => fn -> prefilter_tcp_http_ports(path) end,
        "PRE-FILTER: large packets (>1000 bytes)" => fn -> prefilter_large_packets(path) end,
        "PRE-FILTER: combined (TCP + port 8080)" => fn -> prefilter_combined(path) end
      },
      time: 10,
      warmup: 2,
      memory_time: 2,
      formatters: [
        {Benchee.Formatters.Console, extended_statistics: true}
      ]
    )
  end

  defp parse_raw(path) do
    PcapFileEx.stream(path, decode: false)
    |> Enum.reduce({0, 0}, fn packet, {count, bytes} ->
      {count + 1, bytes + byte_size(packet.data)}
    end)
  end

  defp parse_decoded(path) do
    PcapFileEx.stream(path)
    |> Enum.reduce({0, 0, 0}, fn packet, {count, bytes, http_posts} ->
      http_posts =
        if http_post?(packet) do
          http_posts + 1
        else
          http_posts
        end

      {count + 1, bytes + byte_size(packet.data), http_posts}
    end)
  end

  # Post-filtering functions (Elixir layer)

  defp filter_udp(path) do
    PcapFileEx.stream(path, decode: false)
    |> Filter.by_protocol(:udp)
    |> Enum.reduce({0, 0}, fn packet, {count, bytes} ->
      {count + 1, bytes + byte_size(packet.data)}
    end)
  end

  defp filter_tcp(path) do
    PcapFileEx.stream(path, decode: false)
    |> Filter.by_protocol(:tcp)
    |> Enum.reduce({0, 0}, fn packet, {count, bytes} ->
      {count + 1, bytes + byte_size(packet.data)}
    end)
  end

  defp filter_http_post(path) do
    PcapFileEx.stream(path)
    |> Filter.by_protocol(:http)
    |> Enum.reduce(0, fn packet, acc ->
      if http_post?(packet), do: acc + 1, else: acc
    end)
  end

  defp filter_large_packets(path) do
    PcapFileEx.stream(path, decode: false)
    |> Filter.by_size(1000..65535)
    |> Enum.reduce({0, 0}, fn packet, {count, bytes} ->
      {count + 1, bytes + byte_size(packet.data)}
    end)
  end

  # Pre-filtering functions (Rust layer)

  defp prefilter_udp(path) do
    {:ok, reader} = open_reader(path)

    filters = [PreFilter.protocol("udp")]
    set_filter(reader, filters)

    result =
      stream_from_reader(reader)
      |> Enum.reduce({0, 0}, fn packet, {count, bytes} ->
        {count + 1, bytes + byte_size(packet.data)}
      end)

    close_reader(reader)
    result
  end

  defp prefilter_tcp(path) do
    {:ok, reader} = open_reader(path)

    filters = [PreFilter.protocol("tcp")]
    set_filter(reader, filters)

    result =
      stream_from_reader(reader)
      |> Enum.reduce({0, 0}, fn packet, {count, bytes} ->
        {count + 1, bytes + byte_size(packet.data)}
      end)

    close_reader(reader)
    result
  end

  defp prefilter_tcp_port_80(path) do
    {:ok, reader} = open_reader(path)

    filters = [
      PreFilter.protocol("tcp"),
      PreFilter.port_dest(80)
    ]

    set_filter(reader, filters)

    result =
      stream_from_reader(reader)
      |> Enum.reduce({0, 0}, fn packet, {count, bytes} ->
        {count + 1, bytes + byte_size(packet.data)}
      end)

    close_reader(reader)
    result
  end

  defp prefilter_tcp_http_ports(path) do
    {:ok, reader} = open_reader(path)

    filters = [
      PreFilter.protocol("tcp"),
      PreFilter.any([
        PreFilter.port_dest(80),
        PreFilter.port_dest(443)
      ])
    ]

    set_filter(reader, filters)

    result =
      stream_from_reader(reader)
      |> Enum.reduce({0, 0}, fn packet, {count, bytes} ->
        {count + 1, bytes + byte_size(packet.data)}
      end)

    close_reader(reader)
    result
  end

  defp prefilter_large_packets(path) do
    {:ok, reader} = open_reader(path)

    filters = [PreFilter.size_min(1000)]
    set_filter(reader, filters)

    result =
      stream_from_reader(reader)
      |> Enum.reduce({0, 0}, fn packet, {count, bytes} ->
        {count + 1, bytes + byte_size(packet.data)}
      end)

    close_reader(reader)
    result
  end

  defp prefilter_combined(path) do
    {:ok, reader} = open_reader(path)

    filters = [
      PreFilter.protocol("tcp"),
      PreFilter.port_dest(8080)
    ]

    set_filter(reader, filters)

    result =
      stream_from_reader(reader)
      |> Enum.reduce({0, 0}, fn packet, {count, bytes} ->
        {count + 1, bytes + byte_size(packet.data)}
      end)

    close_reader(reader)
    result
  end

  # Helper functions for reader management

  defp open_reader(path) do
    cond do
      String.ends_with?(path, ".pcapng") -> PcapNg.open(path)
      String.ends_with?(path, ".pcap") -> Pcap.open(path)
      true -> Pcap.open(path)
    end
  end

  defp set_filter(reader, filters) do
    case reader do
      %Pcap{} -> Pcap.set_filter(reader, filters)
      %PcapNg{} -> PcapNg.set_filter(reader, filters)
    end
  end

  defp stream_from_reader(reader) do
    case reader do
      %Pcap{} -> stream_pcap(reader, [])
      %PcapNg{} -> stream_pcapng(reader, [])
    end
  end

  defp stream_pcap(reader, acc) do
    case Pcap.next_packet(reader) do
      {:ok, packet} -> stream_pcap(reader, [packet | acc])
      :eof -> Enum.reverse(acc)
      {:error, _} -> Enum.reverse(acc)
    end
  end

  defp stream_pcapng(reader, acc) do
    case PcapNg.next_packet(reader) do
      {:ok, packet} -> stream_pcapng(reader, [packet | acc])
      :eof -> Enum.reverse(acc)
      {:error, _} -> Enum.reverse(acc)
    end
  end

  defp close_reader(reader) do
    case reader do
      %Pcap{} -> Pcap.close(reader)
      %PcapNg{} -> PcapNg.close(reader)
    end
  end

  defp http_post?(%Packet{} = packet) do
    case packet.decoded do
      %{} = decoded ->
        case Map.get(decoded, :http) do
          %HTTP{type: :request, method: "POST"} -> true
          _ -> fallback_post?(packet)
        end

      _ ->
        fallback_post?(packet)
    end
  end

  defp fallback_post?(packet) do
    case Packet.decode_http(packet) do
      {:ok, %HTTP{type: :request, method: "POST"}} -> true
      _ -> false
    end
  end
end

pcap_path =
  System.get_env("PCAP_BENCH_FILE") ||
    Path.expand("../test/fixtures/large_capture.pcapng", __DIR__)

unless File.exists?(pcap_path) do
  raise ArgumentError,
        "PCAP bench file not found at #{pcap_path}. " <>
          "Set PCAP_BENCH_FILE to point to the large capture generated by capture_heavy_traffic.sh"
end

PcapFileExBench.run(pcap_path)
