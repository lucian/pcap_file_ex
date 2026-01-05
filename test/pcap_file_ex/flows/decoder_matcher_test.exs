defmodule PcapFileEx.Flows.DecoderMatcherTest do
  use ExUnit.Case, async: true

  alias PcapFileEx.Flows.DecoderMatcher

  describe "matches?/2 with map matchers" do
    test "matches exact scope" do
      ctx = %{protocol: :http1, direction: :request, scope: :body}
      assert DecoderMatcher.matches?(%{scope: :body}, ctx)
      refute DecoderMatcher.matches?(%{scope: :multipart_part}, ctx)
    end

    test "matches integer port" do
      ctx = %{protocol: :udp, direction: :datagram, port: 5005}
      assert DecoderMatcher.matches?(%{port: 5005}, ctx)
      refute DecoderMatcher.matches?(%{port: 5006}, ctx)
    end

    test "matches port range" do
      ctx = %{protocol: :udp, direction: :datagram, port: 5005}
      assert DecoderMatcher.matches?(%{port: 5000..5010}, ctx)
      refute DecoderMatcher.matches?(%{port: 6000..6010}, ctx)
    end

    test "matches port list" do
      ctx = %{protocol: :udp, direction: :datagram, port: 5005}
      assert DecoderMatcher.matches?(%{port: [5004, 5005, 5006]}, ctx)
      refute DecoderMatcher.matches?(%{port: [5006, 5007]}, ctx)
    end

    test "matches content_type exact (case-insensitive)" do
      ctx = %{protocol: :http1, direction: :request, content_type: "application/json"}
      assert DecoderMatcher.matches?(%{content_type: "application/json"}, ctx)
      assert DecoderMatcher.matches?(%{content_type: "Application/JSON"}, ctx)
      refute DecoderMatcher.matches?(%{content_type: "text/plain"}, ctx)
    end

    test "matches content_type regex" do
      ctx = %{protocol: :http1, direction: :request, content_type: "application/vnd.3gpp.ngap"}
      assert DecoderMatcher.matches?(%{content_type: ~r/application\/vnd\.3gpp\..*/}, ctx)
      refute DecoderMatcher.matches?(%{content_type: ~r/text\/.*/}, ctx)
    end

    test "matches content_type list" do
      ctx = %{protocol: :http1, direction: :request, content_type: "application/json"}
      assert DecoderMatcher.matches?(%{content_type: ["application/json", "text/json"]}, ctx)
      refute DecoderMatcher.matches?(%{content_type: ["text/plain", "text/html"]}, ctx)
    end

    test "matches content_id exact" do
      ctx = %{protocol: :http1, direction: :request, scope: :multipart_part, content_id: "part1"}
      assert DecoderMatcher.matches?(%{content_id: "part1"}, ctx)
      refute DecoderMatcher.matches?(%{content_id: "part2"}, ctx)
    end

    test "matches content_id regex" do
      ctx = %{
        protocol: :http1,
        direction: :request,
        scope: :multipart_part,
        content_id: "ngap-123"
      }

      assert DecoderMatcher.matches?(%{content_id: ~r/ngap-.*/}, ctx)
      refute DecoderMatcher.matches?(%{content_id: ~r/sbi-.*/}, ctx)
    end

    test "matches method exact (case-insensitive)" do
      ctx = %{protocol: :http1, direction: :request, method: "POST"}
      assert DecoderMatcher.matches?(%{method: "POST"}, ctx)
      assert DecoderMatcher.matches?(%{method: "post"}, ctx)
      refute DecoderMatcher.matches?(%{method: "GET"}, ctx)
    end

    test "matches method list" do
      ctx = %{protocol: :http1, direction: :request, method: "POST"}
      assert DecoderMatcher.matches?(%{method: ["POST", "PUT"]}, ctx)
      refute DecoderMatcher.matches?(%{method: ["GET", "DELETE"]}, ctx)
    end

    test "matches path exact" do
      ctx = %{protocol: :http1, direction: :request, path: "/api/v1/users"}
      assert DecoderMatcher.matches?(%{path: "/api/v1/users"}, ctx)
      refute DecoderMatcher.matches?(%{path: "/api/v2/users"}, ctx)
    end

    test "matches path regex" do
      ctx = %{protocol: :http1, direction: :request, path: "/api/v1/users/123"}
      assert DecoderMatcher.matches?(%{path: ~r/\/api\/v\d+\/users\/.*/}, ctx)
      refute DecoderMatcher.matches?(%{path: ~r/\/admin\/.*/}, ctx)
    end

    test "multiple criteria all must match" do
      ctx = %{
        protocol: :http1,
        direction: :request,
        scope: :body,
        method: "POST",
        path: "/api/upload"
      }

      assert DecoderMatcher.matches?(%{scope: :body, method: "POST"}, ctx)
      refute DecoderMatcher.matches?(%{scope: :body, method: "GET"}, ctx)
      refute DecoderMatcher.matches?(%{scope: :multipart_part, method: "POST"}, ctx)
    end

    test "protocol in matcher map is ignored" do
      ctx = %{protocol: :http1, direction: :request, scope: :body}
      # protocol in matcher map is ignored - it's at decoder_spec level
      assert DecoderMatcher.matches?(%{scope: :body, protocol: :http2}, ctx)
    end
  end

  describe "matches?/2 with function matchers" do
    test "function matcher receives full context" do
      ctx = %{protocol: :http1, direction: :request, scope: :body, method: "POST"}

      matcher = fn c ->
        c.protocol == :http1 and c.method == "POST"
      end

      assert DecoderMatcher.matches?(matcher, ctx)
    end

    test "function matcher returning false" do
      ctx = %{protocol: :http1, direction: :request, scope: :body}
      matcher = fn _c -> false end
      refute DecoderMatcher.matches?(matcher, ctx)
    end

    test "function matcher exceptions are caught and treated as no match" do
      ctx = %{protocol: :http1, direction: :request}
      matcher = fn _c -> raise "boom" end
      refute DecoderMatcher.matches?(matcher, ctx)
    end
  end

  describe "invoke_decoder/3" do
    test "arity-1 function wraps non-error result" do
      decoder = fn payload -> {:decoded, payload} end
      ctx = %{protocol: :udp, direction: :datagram}

      assert {:ok, {:decoded, "test"}} = DecoderMatcher.invoke_decoder(decoder, ctx, "test")
    end

    test "arity-1 function passes through error" do
      decoder = fn _payload -> {:error, :parse_failed} end
      ctx = %{protocol: :udp, direction: :datagram}

      assert {:error, :parse_failed} = DecoderMatcher.invoke_decoder(decoder, ctx, "test")
    end

    test "arity-2 function receives context and payload" do
      decoder = fn ctx, payload ->
        {:ok, %{protocol: ctx.protocol, data: payload}}
      end

      ctx = %{protocol: :udp, direction: :datagram}

      assert {:ok, %{protocol: :udp, data: "test"}} =
               DecoderMatcher.invoke_decoder(decoder, ctx, "test")
    end

    test "arity-2 function can return :skip" do
      decoder = fn _ctx, _payload -> :skip end
      ctx = %{protocol: :udp, direction: :datagram}

      assert :skip = DecoderMatcher.invoke_decoder(decoder, ctx, "test")
    end

    test "arity-2 function can return error" do
      decoder = fn _ctx, _payload -> {:error, :not_my_format} end
      ctx = %{protocol: :udp, direction: :datagram}

      assert {:error, :not_my_format} = DecoderMatcher.invoke_decoder(decoder, ctx, "test")
    end

    test "module decoder calls decode/2" do
      defmodule TestDecoder do
        def decode(ctx, payload) do
          {:ok, %{from: ctx.direction, payload: payload}}
        end
      end

      ctx = %{protocol: :http1, direction: :request}

      assert {:ok, %{from: :request, payload: "test"}} =
               DecoderMatcher.invoke_decoder(TestDecoder, ctx, "test")
    end

    test "decoder exception is caught and returned as error" do
      decoder = fn _payload -> raise "boom" end
      ctx = %{protocol: :udp, direction: :datagram}

      assert {:error, %{exception: %RuntimeError{message: "boom"}, stacktrace: _}} =
               DecoderMatcher.invoke_decoder(decoder, ctx, "test")
    end
  end

  describe "find_and_invoke/3" do
    test "filters by protocol first" do
      udp_decoder = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn _p -> :udp_decoded end
      }

      http1_decoder = %{
        protocol: :http1,
        match: %{},
        decoder: fn _p -> :http1_decoded end
      }

      ctx = %{protocol: :udp, direction: :datagram, port: 5005}

      assert {:ok, :udp_decoded} =
               DecoderMatcher.find_and_invoke([http1_decoder, udp_decoder], ctx, "test")
    end

    test "returns :skip when no decoder matches" do
      decoder = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn _p -> :decoded end
      }

      ctx = %{protocol: :udp, direction: :datagram, port: 6000}
      assert :skip = DecoderMatcher.find_and_invoke([decoder], ctx, "test")
    end

    test "continues to next decoder on :skip" do
      decoder1 = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn _ctx, _payload -> :skip end
      }

      decoder2 = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn _payload -> :second_decoder end
      }

      ctx = %{protocol: :udp, direction: :datagram, port: 5005}

      assert {:ok, :second_decoder} =
               DecoderMatcher.find_and_invoke([decoder1, decoder2], ctx, "test")
    end

    test "stops on error (terminal)" do
      decoder1 = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn _ctx, _payload -> {:error, :parse_failed} end
      }

      decoder2 = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn _payload -> :second_decoder end
      }

      ctx = %{protocol: :udp, direction: :datagram, port: 5005}

      assert {:error, :parse_failed} =
               DecoderMatcher.find_and_invoke([decoder1, decoder2], ctx, "test")
    end

    test "empty decoder list returns :skip" do
      ctx = %{protocol: :udp, direction: :datagram, port: 5005}
      assert :skip = DecoderMatcher.find_and_invoke([], ctx, "test")
    end

    test "missing protocol in context returns :skip" do
      decoder = %{
        protocol: :udp,
        match: %{port: 5005},
        decoder: fn _p -> :decoded end
      }

      # Context without :protocol key - should return :skip, not raise
      ctx = %{direction: :datagram, port: 5005}
      assert :skip = DecoderMatcher.find_and_invoke([decoder], ctx, "test")
    end
  end

  describe "process_result/1" do
    test "ok result becomes custom" do
      assert {:custom, :data} = DecoderMatcher.process_result({:ok, :data})
    end

    test "error result becomes decode_error" do
      assert {:decode_error, :reason} = DecoderMatcher.process_result({:error, :reason})
    end

    test "skip becomes binary_fallback" do
      assert :binary_fallback = DecoderMatcher.process_result(:skip)
    end
  end
end
