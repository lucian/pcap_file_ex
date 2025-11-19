defmodule PcapFileEx.DecoderRegistryPropertyTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias PcapFileEx.{DecoderRegistry, Packet}

  setup do
    # Clean up test decoders
    DecoderRegistry.unregister(:property_test)
    DecoderRegistry.unregister(:no_call_test)

    on_exit(fn ->
      DecoderRegistry.unregister(:property_test)
      DecoderRegistry.unregister(:no_call_test)
    end)

    :ok
  end

  property "context from matcher always reaches decoder" do
    check all(
            context <-
              one_of([
                constant(nil),
                integer(),
                binary(),
                boolean(),
                atom(:alphanumeric),
                list_of(integer(), max_length: 10),
                map_of(atom(:alphanumeric), binary(), max_length: 5)
              ]),
            payload <- binary()
          ) do
      # Track what context the decoder receives
      decoder_pid = self()
      ref = make_ref()

      DecoderRegistry.register(%{
        protocol: :property_test,
        matcher: fn _layers, _payload -> {:match, context} end,
        decoder: fn ctx, _payload ->
          send(decoder_pid, {ref, :context, ctx})
          {:ok, :decoded}
        end,
        fields: []
      })

      packet = build_test_packet(payload)
      assert {:ok, {:property_test, :decoded}} = Packet.decode_registered(packet)

      # Verify the decoder received the exact context from the matcher
      assert_receive {^ref, :context, ^context}, 100

      DecoderRegistry.unregister(:property_test)
    end
  end

  property "matcher returning false never calls decoder" do
    check all(payload <- binary()) do
      # Track if decoder is called
      decoder_pid = self()
      ref = make_ref()

      DecoderRegistry.register(%{
        protocol: :no_call_test,
        matcher: fn _layers, _payload -> false end,
        decoder: fn _ctx, _payload ->
          send(decoder_pid, {ref, :called})
          {:ok, :unreachable}
        end,
        fields: []
      })

      packet = build_test_packet(payload)
      assert :no_match = Packet.decode_registered(packet)

      # Verify decoder was never called
      refute_receive {^ref, :called}, 10

      DecoderRegistry.unregister(:no_call_test)
    end
  end

  property "decoder result is always wrapped in :ok tuple if not already" do
    check all(
            result <-
              one_of([
                constant(:ok),
                constant(:error),
                binary(),
                integer(),
                boolean(),
                atom(:alphanumeric),
                list_of(integer(), max_length: 10),
                map_of(atom(:alphanumeric), binary(), max_length: 5)
              ]),
            payload <- binary()
          ) do
      DecoderRegistry.register(%{
        protocol: :property_test,
        matcher: fn _layers, _payload -> {:match, nil} end,
        decoder: fn _ctx, _payload ->
          # Return various types - should all be wrapped
          result
        end,
        fields: []
      })

      packet = build_test_packet(payload)

      case Packet.decode_registered(packet) do
        {:ok, {:property_test, _decoded}} -> :ok
        {:error, _} -> :ok
        other -> flunk("Expected {:ok, _} or {:error, _}, got: #{inspect(other)}")
      end

      DecoderRegistry.unregister(:property_test)
    end
  end

  property "matcher exceptions are caught and treated as false" do
    check all(payload <- binary()) do
      DecoderRegistry.register(%{
        protocol: :property_test,
        matcher: fn _layers, _payload ->
          # Always raise
          raise "test exception"
        end,
        decoder: fn _ctx, _payload -> {:ok, :unreachable} end,
        fields: []
      })

      packet = build_test_packet(payload)

      # Should not crash, protocol should not be detected
      assert :property_test not in packet.protocols

      DecoderRegistry.unregister(:property_test)
    end
  end

  property "decoder exceptions are caught and returned as {:error, exception}" do
    check all(payload <- binary()) do
      DecoderRegistry.register(%{
        protocol: :property_test,
        matcher: fn _layers, _payload -> {:match, nil} end,
        decoder: fn _ctx, _payload ->
          # Always raise
          raise ArgumentError, "test error"
        end,
        fields: []
      })

      packet = build_test_packet(payload)

      # Should return error, not crash
      assert {:error, %ArgumentError{}} = Packet.decode_registered(packet)

      DecoderRegistry.unregister(:property_test)
    end
  end

  property "old API (boolean matcher, arity-1 decoder) always works" do
    check all(
            should_match <- boolean(),
            payload <- binary()
          ) do
      import ExUnit.CaptureIO

      # Suppress deprecation warnings in property tests
      capture_io(:stderr, fn ->
        DecoderRegistry.register(%{
          protocol: :property_test,
          # Old API: returns boolean
          matcher: fn _layers, _payload -> should_match end,
          # Old API: arity-1
          decoder: fn _payload -> {:ok, :decoded_old_api} end,
          fields: []
        })
      end)

      packet = build_test_packet(payload)

      result = Packet.decode_registered(packet)

      if should_match do
        assert {:ok, {:property_test, :decoded_old_api}} = result
      else
        assert :no_match = result
      end

      DecoderRegistry.unregister(:property_test)
    end
  end

  property "context can be any valid Elixir term" do
    check all(
            context <-
              one_of([
                constant(nil),
                integer(),
                float(),
                binary(),
                boolean(),
                atom(:alphanumeric),
                list_of(integer()),
                map_of(atom(:alphanumeric), binary()),
                tuple({integer(), binary()})
              ]),
            payload <- binary()
          ) do
      decoder_pid = self()
      ref = make_ref()

      DecoderRegistry.register(%{
        protocol: :property_test,
        matcher: fn _layers, _payload -> {:match, context} end,
        decoder: fn ctx, _payload ->
          send(decoder_pid, {ref, :received_context, ctx})
          {:ok, :done}
        end,
        fields: []
      })

      packet = build_test_packet(payload)
      assert {:ok, {:property_test, :done}} = Packet.decode_registered(packet)

      # Context should be preserved exactly
      assert_receive {^ref, :received_context, ^context}, 100

      DecoderRegistry.unregister(:property_test)
    end
  end

  defp build_test_packet(payload) do
    data = build_udp_data(payload)

    map = %{
      timestamp_secs: DateTime.to_unix(DateTime.utc_now()),
      timestamp_nanos: 0,
      orig_len: byte_size(data),
      data: :binary.bin_to_list(data),
      datalink: "ipv4"
    }

    Packet.from_map(map)
  end

  defp build_udp_data(payload) do
    payload_bin = payload
    udp_len = 8 + byte_size(payload_bin)
    total_len = 20 + udp_len

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
      17,
      # UDP protocol
      0x00,
      0x00,
      # Source IP
      127,
      0,
      0,
      1,
      # Dest IP
      127,
      0,
      0,
      1,
      # UDP header
      40_000::16,
      # src port
      8898::16,
      # dst port
      udp_len::16,
      0x00,
      0x00,
      payload_bin::binary
    >>
  end
end
