defmodule PcapFileEx.TimestampPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias PcapFileEx.Timestamp
  import PcapFileEx.PropertyGenerators

  describe "Timestamp.compare/2" do
    property "comparison is reflexive (ts == ts)" do
      check all ts <- mixed_timestamp_generator() do
        assert Timestamp.compare(ts, ts) == :eq
      end
    end

    property "comparison is transitive" do
      check all ts1 <- mixed_timestamp_generator(),
                ts2 <- mixed_timestamp_generator(),
                ts3 <- mixed_timestamp_generator() do
        cmp12 = Timestamp.compare(ts1, ts2)
        cmp23 = Timestamp.compare(ts2, ts3)
        cmp13 = Timestamp.compare(ts1, ts3)

        # If ts1 < ts2 and ts2 < ts3, then ts1 < ts3
        if cmp12 == :lt and cmp23 == :lt do
          assert cmp13 == :lt
        end

        # If ts1 > ts2 and ts2 > ts3, then ts1 > ts3
        if cmp12 == :gt and cmp23 == :gt do
          assert cmp13 == :gt
        end

        # If ts1 == ts2 and ts2 == ts3, then ts1 == ts3
        if cmp12 == :eq and cmp23 == :eq do
          assert cmp13 == :eq
        end
      end
    end

    property "comparison is antisymmetric" do
      check all ts1 <- mixed_timestamp_generator(),
                ts2 <- mixed_timestamp_generator() do
        cmp12 = Timestamp.compare(ts1, ts2)
        cmp21 = Timestamp.compare(ts2, ts1)

        case cmp12 do
          :lt -> assert cmp21 == :gt
          :gt -> assert cmp21 == :lt
          :eq -> assert cmp21 == :eq
        end
      end
    end

    property "comparison respects total ordering" do
      check all ts1 <- mixed_timestamp_generator(),
                ts2 <- mixed_timestamp_generator() do
        # Every pair must have exactly one of: <, ==, >
        cmp = Timestamp.compare(ts1, ts2)
        assert cmp in [:lt, :eq, :gt]
      end
    end
  end

  describe "Timestamp.diff/2" do
    property "diff is commutative with sign flip" do
      check all ts1 <- mixed_timestamp_generator(),
                ts2 <- mixed_timestamp_generator() do
        diff12 = Timestamp.diff(ts1, ts2)
        diff21 = Timestamp.diff(ts2, ts1)

        assert diff12 == -diff21
      end
    end

    property "diff of equal timestamps is zero" do
      check all ts <- mixed_timestamp_generator() do
        assert Timestamp.diff(ts, ts) == 0
      end
    end

    property "diff sign agrees with compare" do
      check all ts1 <- mixed_timestamp_generator(),
                ts2 <- mixed_timestamp_generator() do
        diff = Timestamp.diff(ts1, ts2)
        cmp = Timestamp.compare(ts1, ts2)

        case cmp do
          :lt -> assert diff < 0
          :eq -> assert diff == 0
          :gt -> assert diff > 0
        end
      end
    end
  end

  describe "Timestamp.to_unix_nanos/1" do
    property "to_unix_nanos is monotonic with compare" do
      check all ts1 <- mixed_timestamp_generator(),
                ts2 <- mixed_timestamp_generator() do
        nanos1 = Timestamp.to_unix_nanos(ts1)
        nanos2 = Timestamp.to_unix_nanos(ts2)
        cmp = Timestamp.compare(ts1, ts2)

        case cmp do
          :lt -> assert nanos1 < nanos2
          :eq -> assert nanos1 == nanos2
          :gt -> assert nanos1 > nanos2
        end
      end
    end

    property "to_unix_nanos produces non-negative values" do
      check all ts <- mixed_timestamp_generator() do
        nanos = Timestamp.to_unix_nanos(ts)
        assert nanos >= 0
      end
    end

    property "to_unix_nanos matches manual calculation" do
      check all ts <- mixed_timestamp_generator() do
        nanos = Timestamp.to_unix_nanos(ts)
        expected = ts.secs * 1_000_000_000 + ts.nanos

        assert nanos == expected
      end
    end
  end

  describe "Timestamp.to_datetime/1 and from_datetime/1" do
    property "DateTime round-trip preserves microsecond precision" do
      check all dt <- datetime_generator() do
        ts = Timestamp.from_datetime(dt)
        result = Timestamp.to_datetime(ts)

        # DateTime only has microsecond precision, so we compare
        # using DateTime.compare which ignores subsecond differences
        assert DateTime.compare(result, dt) == :eq

        # More precise check: the microsecond components should match
        {result_micros, _} = result.microsecond
        {dt_micros, _} = dt.microsecond
        assert result_micros == dt_micros
      end
    end

    property "from_datetime produces timestamps with valid nanos" do
      check all dt <- datetime_generator() do
        ts = Timestamp.from_datetime(dt)

        assert ts.secs >= 0
        assert ts.nanos >= 0
        assert ts.nanos <= 999_999_999
      end
    end

    property "from_datetime preserves seconds component" do
      check all dt <- datetime_generator() do
        ts = Timestamp.from_datetime(dt)
        expected_secs = DateTime.to_unix(dt, :second)

        assert ts.secs == expected_secs
      end
    end
  end

  describe "Timestamp invariants" do
    property "nanos always within valid range" do
      check all ts <- mixed_timestamp_generator() do
        assert ts.nanos >= 0
        assert ts.nanos <= 999_999_999
      end
    end

    property "secs is always non-negative" do
      check all ts <- mixed_timestamp_generator() do
        assert ts.secs >= 0
      end
    end

    property "new/2 enforces nanosecond bounds" do
      check all secs <- integer(0..2_000_000_000),
                nanos <- integer(0..999_999_999) do
        ts = Timestamp.new(secs, nanos)
        assert ts.secs == secs
        assert ts.nanos == nanos
      end
    end
  end

  describe "Timestamp.to_string/1 (via String.Chars protocol)" do
    property "to_string always produces a string" do
      check all ts <- mixed_timestamp_generator() do
        result = to_string(ts)
        assert is_binary(result)
        assert String.length(result) > 0
      end
    end

    property "to_string output is parseable as ISO8601-like" do
      check all ts <- mixed_timestamp_generator() do
        result = to_string(ts)

        # Should contain date/time components
        # Format: YYYY-MM-DD HH:MM:SS.subsecZ or ISO8601
        assert result =~ ~r/\d{4}/
        # Year
        assert result =~ ~r/\d{2}:\d{2}/
        # Time component
      end
    end
  end
end
