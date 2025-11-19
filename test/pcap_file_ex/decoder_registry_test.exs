defmodule PcapFileEx.DecoderRegistryTest do
  use ExUnit.Case, async: false

  alias PcapFileEx.{DecoderRegistry, DisplayFilter, Packet}

  @payload ~s({"sensor":"alpha","value":21})

  setup do
    DecoderRegistry.unregister(:custom_json)

    on_exit(fn ->
      DecoderRegistry.unregister(:custom_json)
    end)

    :ok
  end

  test "registers custom decoder and augments protocol stack" do
    DecoderRegistry.register(%{
      protocol: :custom_json,
      matcher: fn _layers, payload ->
        String.contains?(IO.iodata_to_binary(payload), "sensor")
      end,
      decoder: fn payload ->
        {:ok, Jason.decode!(IO.iodata_to_binary(payload))}
      end,
      fields: [
        %{id: "custom_json.value", type: :integer, extractor: fn decoded -> decoded["value"] end},
        %{id: "custom_json.sensor", type: :string, extractor: fn decoded -> decoded["sensor"] end}
      ]
    })

    packet = build_udp_packet(@payload)

    assert :custom_json in packet.protocols
    assert {:ok, {:custom_json, decoded}} = Packet.decode_registered(packet)
    assert decoded["sensor"] == "alpha"

    {:ok, fun} = DisplayFilter.compile("custom_json.value == 21")

    filtered =
      [Packet.attach_decoded(packet)]
      |> DisplayFilter.run(fun)
      |> Enum.to_list()

    assert length(filtered) == 1
  end

  defp build_udp_packet(payload) do
    data = ipv4_udp_packet(payload)

    map = %{
      timestamp_secs: DateTime.to_unix(DateTime.utc_now()),
      timestamp_nanos: 0,
      orig_len: byte_size(data),
      data: :binary.bin_to_list(data),
      datalink: "ipv4"
    }

    Packet.from_map(map)
  end

  defp ipv4_udp_packet(payload, opts \\ []) do
    src_ip = Keyword.get(opts, :src_ip, {127, 0, 0, 1})
    dst_ip = Keyword.get(opts, :dst_ip, {127, 0, 0, 1})
    src_port = Keyword.get(opts, :src_port, 40_000)
    dst_port = Keyword.get(opts, :dst_port, 8898)

    payload_bin = payload
    udp_len = 8 + byte_size(payload_bin)
    total_len = 20 + udp_len

    <<
      0x45,
      0x00,
      total_len::16,
      0x12,
      0x34,
      0x00,
      0x00,
      64,
      17,
      0x00,
      0x00,
      ip_tuple_to_binary(src_ip)::binary-size(4),
      ip_tuple_to_binary(dst_ip)::binary-size(4),
      src_port::16,
      dst_port::16,
      udp_len::16,
      0x00,
      0x00,
      payload_bin::binary
    >>
  end

  defp ip_tuple_to_binary({a, b, c, d}) do
    <<a, b, c, d>>
  end

  describe "context passing (new API)" do
    test "matcher can return context to decoder" do
      DecoderRegistry.register(%{
        protocol: :context_test,
        matcher: fn _layers, payload ->
          payload_str = IO.iodata_to_binary(payload)

          if String.contains?(payload_str, "CONTEXT") do
            {:match, %{found_at: byte_size(payload_str), marker: "test"}}
          else
            false
          end
        end,
        decoder: fn context, _payload ->
          {:ok, %{context: context}}
        end,
        fields: []
      })

      packet = build_udp_packet("DATA CONTEXT HERE")

      assert :context_test in packet.protocols
      assert {:ok, {:context_test, decoded}} = Packet.decode_registered(packet)
      assert decoded.context.marker == "test"
      assert is_integer(decoded.context.found_at)

      DecoderRegistry.unregister(:context_test)
    end

    test "matcher returning false prevents decoder invocation" do
      decoder_called = :erlang.unique_integer()

      DecoderRegistry.register(%{
        protocol: :no_match_test,
        matcher: fn _layers, _payload -> false end,
        decoder: fn _context, _payload ->
          # This should never be called
          :persistent_term.put(decoder_called, true)
          {:ok, :should_not_reach}
        end,
        fields: []
      })

      packet = build_udp_packet("DATA")

      assert :no_match = Packet.decode_registered(packet)
      assert :undefined == :persistent_term.get(decoder_called, :undefined)

      DecoderRegistry.unregister(:no_match_test)
    end

    test "context can be any term" do
      test_contexts = [
        nil,
        42,
        "string",
        [:list, :of, :atoms],
        %{map: "data", nested: %{deep: true}},
        {:tuple, :data}
      ]

      for ctx <- test_contexts do
        DecoderRegistry.register(%{
          protocol: :context_any_test,
          matcher: fn _layers, _payload -> {:match, ctx} end,
          decoder: fn context, _payload -> {:ok, {:received, context}} end,
          fields: []
        })

        packet = build_udp_packet("test")

        assert {:ok, {:context_any_test, {:received, ^ctx}}} = Packet.decode_registered(packet)

        DecoderRegistry.unregister(:context_any_test)
      end
    end
  end

  describe "backward compatibility (old API)" do
    test "arity-1 decoder still works" do
      import ExUnit.CaptureIO

      output =
        capture_io(:stderr, fn ->
          DecoderRegistry.register(%{
            protocol: :legacy_test,
            matcher: fn _layers, payload ->
              String.contains?(IO.iodata_to_binary(payload), "LEGACY")
            end,
            decoder: fn payload ->
              {:ok, String.upcase(IO.iodata_to_binary(payload))}
            end,
            fields: []
          })
        end)

      # Should emit deprecation warning
      assert output =~ "deprecated"
      assert output =~ "v1.0.0"

      packet = build_udp_packet("LEGACY data")

      assert :legacy_test in packet.protocols
      assert {:ok, {:legacy_test, decoded}} = Packet.decode_registered(packet)
      assert String.contains?(decoded, "LEGACY DATA")

      DecoderRegistry.unregister(:legacy_test)
    end

    test "mixed old and new decoders coexist" do
      import ExUnit.CaptureIO

      # Register old API decoder (with warning)
      capture_io(:stderr, fn ->
        DecoderRegistry.register(%{
          protocol: :old_api,
          matcher: fn _layers, payload ->
            String.contains?(IO.iodata_to_binary(payload), "OLD")
          end,
          decoder: fn _payload -> {:ok, :old} end,
          fields: []
        })
      end)

      # Register new API decoder (no warning)
      DecoderRegistry.register(%{
        protocol: :new_api,
        matcher: fn _layers, payload ->
          if String.contains?(IO.iodata_to_binary(payload), "NEW") do
            {:match, :context}
          else
            false
          end
        end,
        decoder: fn _context, _payload -> {:ok, :new} end,
        fields: []
      })

      # Both should work
      old_packet = build_udp_packet("OLD data")
      new_packet = build_udp_packet("NEW data")

      assert {:ok, {:old_api, :old}} = Packet.decode_registered(old_packet)
      assert {:ok, {:new_api, :new}} = Packet.decode_registered(new_packet)

      DecoderRegistry.unregister(:old_api)
      DecoderRegistry.unregister(:new_api)
    end

    test "old API matcher returning true is converted to {:match, nil}" do
      import ExUnit.CaptureIO

      capture_io(:stderr, fn ->
        DecoderRegistry.register(%{
          protocol: :old_matcher_test,
          # Old style: returns boolean
          matcher: fn _layers, _payload -> true end,
          # Old style: arity-1
          decoder: fn _payload -> {:ok, :decoded} end,
          fields: []
        })
      end)

      packet = build_udp_packet("test")

      # Should still work (backward compatible)
      assert {:ok, {:old_matcher_test, :decoded}} = Packet.decode_registered(packet)

      DecoderRegistry.unregister(:old_matcher_test)
    end
  end

  describe "error handling" do
    test "matcher exception returns false" do
      DecoderRegistry.register(%{
        protocol: :crash_test,
        matcher: fn _layers, _payload ->
          raise "matcher crash"
        end,
        decoder: fn _context, _payload -> {:ok, :unreachable} end,
        fields: []
      })

      packet = build_udp_packet("data")

      # Matcher crash should be caught, treated as false
      assert :crash_test not in packet.protocols

      DecoderRegistry.unregister(:crash_test)
    end

    test "decoder exception returns error tuple" do
      DecoderRegistry.register(%{
        protocol: :decoder_crash,
        matcher: fn _layers, _payload -> {:match, :ctx} end,
        decoder: fn _context, _payload ->
          raise ArgumentError, "decoder crash"
        end,
        fields: []
      })

      packet = build_udp_packet("data")

      assert :decoder_crash in packet.protocols
      assert {:error, %ArgumentError{}} = Packet.decode_registered(packet)

      DecoderRegistry.unregister(:decoder_crash)
    end

    test "decoder can return {:error, reason}" do
      DecoderRegistry.register(%{
        protocol: :error_return_test,
        matcher: fn _layers, _payload -> {:match, :ctx} end,
        decoder: fn _context, _payload ->
          {:error, :invalid_format}
        end,
        fields: []
      })

      packet = build_udp_packet("data")

      assert {:error, :invalid_format} = Packet.decode_registered(packet)

      DecoderRegistry.unregister(:error_return_test)
    end
  end

  describe "HTTP decoder optimization" do
    test "HTTP decoder uses new context passing API" do
      # The built-in HTTP decoder should now decode once and cache result
      # This is tested implicitly by checking that HTTP decoding works
      http_request = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
      packet = build_tcp_packet(http_request)

      assert :http in packet.protocols
      assert {:ok, {:http, decoded}} = Packet.decode_registered(packet)
      assert decoded.method == "GET"
      assert decoded.uri == "/test"
    end
  end

  defp build_tcp_packet(payload) do
    data = ipv4_tcp_packet(payload)

    map = %{
      timestamp_secs: DateTime.to_unix(DateTime.utc_now()),
      timestamp_nanos: 0,
      orig_len: byte_size(data),
      data: :binary.bin_to_list(data),
      datalink: "ipv4"
    }

    Packet.from_map(map)
  end

  defp ipv4_tcp_packet(payload, opts \\ []) do
    src_ip = Keyword.get(opts, :src_ip, {127, 0, 0, 1})
    dst_ip = Keyword.get(opts, :dst_ip, {127, 0, 0, 1})
    src_port = Keyword.get(opts, :src_port, 40_000)
    dst_port = Keyword.get(opts, :dst_port, 80)

    payload_bin = payload
    tcp_len = 20 + byte_size(payload_bin)
    total_len = 20 + tcp_len

    <<
      # IPv4 header
      0x45,
      0x00,
      total_len::16,
      0x12,
      0x34,
      0x00,
      0x00,
      64,
      6,
      # TCP protocol
      0x00,
      0x00,
      ip_tuple_to_binary(src_ip)::binary-size(4),
      ip_tuple_to_binary(dst_ip)::binary-size(4),
      # TCP header
      src_port::16,
      dst_port::16,
      # Sequence number
      0::32,
      # Acknowledgment number
      0::32,
      # Data offset (5 words = 20 bytes), flags
      0x50,
      0x18,
      # Window size
      0xFF::16,
      # Checksum
      0x00,
      0x00,
      # Urgent pointer
      0x00,
      0x00,
      payload_bin::binary
    >>
  end
end
