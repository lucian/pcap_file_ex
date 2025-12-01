defmodule PcapFileEx.DecoderRegistryIntegrationTest do
  use ExUnit.Case, async: false

  alias PcapFileEx.{DecoderRegistry, Packet}

  setup do
    # Clean up any test decoders
    DecoderRegistry.unregister(:tcp_with_port)
    DecoderRegistry.unregister(:layer_context_test)

    on_exit(fn ->
      DecoderRegistry.unregister(:tcp_with_port)
      DecoderRegistry.unregister(:layer_context_test)
    end)

    :ok
  end

  describe "context passing with real PCAP files" do
    test "extract TCP port from layers and pass to decoder" do
      # Register custom decoder that extracts TCP port from layers
      DecoderRegistry.register(%{
        protocol: :tcp_with_port,
        matcher: fn layers, _payload ->
          # Find TCP layer and extract source port
          Enum.find_value(layers, fn
            {:tcp, src_port, _dst_port, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} ->
              {:match, %{src_port: src_port}}

            _ ->
              nil
          end)
        end,
        decoder: fn context, payload ->
          {:ok, %{port: context.src_port, data: payload, data_size: byte_size(payload)}}
        end,
        fields: []
      })

      # Process real PCAP file
      {:ok, packets} = PcapFileEx.read_all("test/fixtures/sample.pcap")

      decoded_packets =
        packets
        |> Enum.map(&Packet.decode_registered/1)
        |> Enum.filter(&match?({:ok, {:tcp_with_port, _}}, &1))

      # Should find at least some TCP packets
      refute Enum.empty?(decoded_packets)

      # Verify context was passed correctly
      for {:ok, {:tcp_with_port, decoded}} <- decoded_packets do
        assert is_integer(decoded.port)
        assert decoded.port > 0
        assert is_binary(decoded.data)
        assert is_integer(decoded.data_size)
      end
    end

    test "extract multiple layer information via context" do
      # Register decoder that extracts IP and TCP information
      DecoderRegistry.register(%{
        protocol: :layer_context_test,
        matcher: fn layers, _payload ->
          # Extract IP addresses and TCP ports
          ip_info =
            Enum.find_value(layers, fn
              {:ipv4, _, _, _, _, _, _, _, _, _, _, _, src, dst, _} ->
                %{src_ip: format_ip(src), dst_ip: format_ip(dst)}

              _ ->
                nil
            end)

          tcp_info =
            Enum.find_value(layers, fn
              {:tcp, src_port, dst_port, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} ->
                %{src_port: src_port, dst_port: dst_port}

              _ ->
                nil
            end)

          if ip_info && tcp_info do
            {:match, Map.merge(ip_info, tcp_info)}
          else
            false
          end
        end,
        decoder: fn context, _payload ->
          {:ok, context}
        end,
        fields: []
      })

      # Process real PCAP file
      {:ok, packets} = PcapFileEx.read_all("test/fixtures/sample.pcap")

      decoded_packets =
        packets
        |> Enum.map(&Packet.decode_registered/1)
        |> Enum.filter(&match?({:ok, {:layer_context_test, _}}, &1))

      # Should find TCP packets with IP information
      refute Enum.empty?(decoded_packets)

      # Verify all context fields are present
      for {:ok, {:layer_context_test, decoded}} <- decoded_packets do
        assert is_binary(decoded.src_ip)
        assert is_binary(decoded.dst_ip)
        assert is_integer(decoded.src_port)
        assert is_integer(decoded.dst_port)
      end
    end

    test "context passing works with streaming" do
      # Register decoder
      DecoderRegistry.register(%{
        protocol: :tcp_with_port,
        matcher: fn layers, _payload ->
          Enum.find_value(layers, fn
            {:tcp, src_port, _dst_port, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _} ->
              {:match, %{src_port: src_port}}

            _ ->
              nil
          end)
        end,
        decoder: fn context, _payload ->
          {:ok, %{port: context.src_port}}
        end,
        fields: []
      })

      # Stream and decode
      decoded_count =
        PcapFileEx.stream!("test/fixtures/sample.pcap")
        |> Stream.map(&Packet.decode_registered/1)
        |> Enum.count(&match?({:ok, {:tcp_with_port, _}}, &1))

      assert decoded_count > 0
    end
  end

  defp format_ip({_, _, _, _} = ip), do: ip |> :inet.ntoa() |> to_string()
  defp format_ip({_, _, _, _, _, _, _, _} = ip), do: ip |> :inet.ntoa() |> to_string()
  defp format_ip(_), do: nil
end
