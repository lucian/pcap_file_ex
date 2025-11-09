defmodule PcapFileEx.TimestampTest do
  use ExUnit.Case, async: true
  alias PcapFileEx.Timestamp

  doctest PcapFileEx.Timestamp

  describe "new/2" do
    test "creates timestamp with valid values" do
      ts = Timestamp.new(1_731_065_049, 735_188_123)
      assert %Timestamp{secs: 1_731_065_049, nanos: 735_188_123} = ts
    end

    test "creates timestamp with zero values" do
      ts = Timestamp.new(0, 0)
      assert %Timestamp{secs: 0, nanos: 0} = ts
    end

    test "creates timestamp with maximum nanoseconds" do
      ts = Timestamp.new(100, 999_999_999)
      assert %Timestamp{secs: 100, nanos: 999_999_999} = ts
    end
  end

  describe "to_unix_nanos/1" do
    test "converts timestamp to total nanoseconds" do
      ts = Timestamp.new(1_731_065_049, 735_188_123)
      assert Timestamp.to_unix_nanos(ts) == 1_731_065_049_735_188_123
    end

    test "handles zero timestamp" do
      ts = Timestamp.new(0, 0)
      assert Timestamp.to_unix_nanos(ts) == 0
    end

    test "handles timestamp with only nanoseconds" do
      ts = Timestamp.new(0, 999_999_999)
      assert Timestamp.to_unix_nanos(ts) == 999_999_999
    end

    test "handles large timestamps" do
      ts = Timestamp.new(2_000_000_000, 500_000_000)
      assert Timestamp.to_unix_nanos(ts) == 2_000_000_000_500_000_000
    end
  end

  describe "to_datetime/1" do
    test "converts timestamp to DateTime with precision loss" do
      ts = Timestamp.new(1_731_065_049, 735_188_123)
      dt = Timestamp.to_datetime(ts)

      assert dt == ~U[2024-11-08 11:24:09.735188Z]
      # Note: 735188123 nanos becomes 735188 micros (lost last 3 digits)
    end

    test "handles timestamp at epoch" do
      ts = Timestamp.new(0, 0)
      dt = Timestamp.to_datetime(ts)

      assert dt == ~U[1970-01-01 00:00:00.000000Z]
    end

    test "truncates nanoseconds to microseconds" do
      # 123 nanoseconds should be lost in conversion
      ts = Timestamp.new(100, 500_123)
      dt = Timestamp.to_datetime(ts)

      assert {500, 6} = dt.microsecond
      # Verify 500 microseconds, not 500123
    end

    test "handles sub-microsecond precision" do
      # Test that sub-microsecond values are truncated, not rounded
      # 1999 nanos = 1 micro (truncated)
      ts1 = Timestamp.new(100, 1_999)
      # 2000 nanos = 2 micros
      ts2 = Timestamp.new(100, 2_000)

      dt1 = Timestamp.to_datetime(ts1)
      dt2 = Timestamp.to_datetime(ts2)

      assert {1, 6} = dt1.microsecond
      assert {2, 6} = dt2.microsecond
    end
  end

  describe "from_datetime/2" do
    test "creates timestamp from DateTime with microsecond resolution" do
      dt = ~U[2024-11-08 11:24:09.735188Z]
      ts = Timestamp.from_datetime(dt)

      assert %Timestamp{secs: 1_731_065_049, nanos: 735_188_000} = ts
      # Note: microseconds are multiplied by 1000 to get nanoseconds
    end

    test "handles DateTime at epoch" do
      dt = ~U[1970-01-01 00:00:00.000000Z]
      ts = Timestamp.from_datetime(dt)

      assert %Timestamp{secs: 0, nanos: 0} = ts
    end

    test "preserves microsecond precision" do
      dt = ~U[2024-11-08 11:24:09.123456Z]
      ts = Timestamp.from_datetime(dt)

      assert %Timestamp{secs: _, nanos: 123_456_000} = ts
    end

    test "handles DateTime with zero microseconds" do
      dt = ~U[2024-11-08 11:24:09.000000Z]
      ts = Timestamp.from_datetime(dt)

      assert %Timestamp{secs: _, nanos: 0} = ts
    end

    test "accepts nanosecond resolution parameter" do
      dt = ~U[2024-11-08 11:24:09.735188Z]
      ts = Timestamp.from_datetime(dt, :nanosecond)

      assert %Timestamp{secs: 1_731_065_049, nanos: 735_188_000} = ts
    end
  end

  describe "compare/2" do
    test "returns :lt when first timestamp is earlier" do
      ts1 = Timestamp.new(100, 500)
      ts2 = Timestamp.new(100, 600)

      assert Timestamp.compare(ts1, ts2) == :lt
    end

    test "returns :gt when first timestamp is later" do
      ts1 = Timestamp.new(200, 500)
      ts2 = Timestamp.new(100, 600)

      assert Timestamp.compare(ts1, ts2) == :gt
    end

    test "returns :eq when timestamps are equal" do
      ts1 = Timestamp.new(100, 500)
      ts2 = Timestamp.new(100, 500)

      assert Timestamp.compare(ts1, ts2) == :eq
    end

    test "compares by seconds first" do
      ts1 = Timestamp.new(101, 0)
      ts2 = Timestamp.new(100, 999_999_999)

      assert Timestamp.compare(ts1, ts2) == :gt
    end

    test "compares nanoseconds when seconds are equal" do
      ts1 = Timestamp.new(100, 1)
      ts2 = Timestamp.new(100, 2)

      assert Timestamp.compare(ts1, ts2) == :lt
    end

    test "works with Enum.sort_by" do
      ts1 = Timestamp.new(100, 300)
      ts2 = Timestamp.new(100, 100)
      ts3 = Timestamp.new(100, 200)
      ts4 = Timestamp.new(99, 999_999_999)

      sorted = Enum.sort([ts1, ts2, ts3, ts4], Timestamp)

      assert sorted == [ts4, ts2, ts3, ts1]
    end
  end

  describe "diff/2" do
    test "returns positive when first is later" do
      ts1 = Timestamp.new(100, 600)
      ts2 = Timestamp.new(100, 500)

      assert Timestamp.diff(ts1, ts2) == 100
    end

    test "returns negative when first is earlier" do
      ts1 = Timestamp.new(100, 500)
      ts2 = Timestamp.new(100, 600)

      assert Timestamp.diff(ts1, ts2) == -100
    end

    test "returns zero when timestamps are equal" do
      ts1 = Timestamp.new(100, 500)
      ts2 = Timestamp.new(100, 500)

      assert Timestamp.diff(ts1, ts2) == 0
    end

    test "calculates difference across seconds" do
      ts1 = Timestamp.new(101, 0)
      ts2 = Timestamp.new(100, 0)

      assert Timestamp.diff(ts1, ts2) == 1_000_000_000
    end

    test "handles complex differences" do
      ts1 = Timestamp.new(101, 500)
      ts2 = Timestamp.new(100, 600)

      # Difference: (101 * 1e9 + 500) - (100 * 1e9 + 600) = 1e9 - 100
      assert Timestamp.diff(ts1, ts2) == 999_999_900
    end

    test "handles large time spans" do
      ts1 = Timestamp.new(2_000_000_000, 0)
      ts2 = Timestamp.new(1_000_000_000, 0)

      assert Timestamp.diff(ts1, ts2) == 1_000_000_000_000_000_000
    end
  end

  describe "String.Chars protocol" do
    test "converts timestamp to string with full precision" do
      ts = Timestamp.new(1_731_065_049, 735_188_123)
      str = to_string(ts)

      # Should show all 9 digits of nanosecond precision
      assert str =~ "735188123"
    end

    test "handles timestamps without sub-microsecond precision" do
      ts = Timestamp.new(1_731_065_049, 735_188_000)
      str = to_string(ts)

      # When sub-microsecond is 0, may show standard DateTime format
      assert is_binary(str)
      assert str =~ "2024-11-08"
    end

    test "produces readable output" do
      ts = Timestamp.new(0, 0)
      str = to_string(ts)

      assert is_binary(str)
      assert str =~ "1970"
    end
  end

  describe "Inspect protocol" do
    test "produces inspectable output" do
      ts = Timestamp.new(1_731_065_049, 735_188_123)
      inspected = inspect(ts)

      assert inspected =~ "PcapFileEx.Timestamp"
      assert is_binary(inspected)
    end

    test "shows readable format" do
      ts = Timestamp.new(100, 500_000_000)
      inspected = inspect(ts)

      assert is_binary(inspected)
    end
  end

  describe "roundtrip conversions" do
    test "DateTime -> Timestamp -> DateTime preserves microsecond precision" do
      original = ~U[2024-11-08 11:24:09.735188Z]
      ts = Timestamp.from_datetime(original)
      converted = Timestamp.to_datetime(ts)

      assert original == converted
    end

    test "Timestamp -> DateTime -> Timestamp loses nanosecond precision" do
      original = Timestamp.new(1_731_065_049, 735_188_123)
      dt = Timestamp.to_datetime(original)
      converted = Timestamp.from_datetime(dt)

      # Lost the last 3 digits (123 nanos)
      assert %Timestamp{secs: 1_731_065_049, nanos: 735_188_000} = converted
      refute converted == original
    end
  end

  describe "edge cases" do
    test "handles year 2038 problem (32-bit timestamp overflow)" do
      # Unix timestamp 2^31 - 1 = 2147483647 (Jan 19, 2038)
      ts = Timestamp.new(2_147_483_647, 999_999_999)
      dt = Timestamp.to_datetime(ts)

      assert dt.year == 2038
    end

    test "handles timestamps beyond year 2262" do
      # This is where nanosecond timestamps overflow 64-bit integers
      # But our implementation uses separate secs and nanos
      ts = Timestamp.new(10_000_000_000, 0)
      nanos = Timestamp.to_unix_nanos(ts)

      assert nanos == 10_000_000_000_000_000_000
    end

    test "handles nanosecond boundary" do
      ts1 = Timestamp.new(100, 999_999_999)
      ts2 = Timestamp.new(101, 0)

      assert Timestamp.compare(ts1, ts2) == :lt
      assert Timestamp.diff(ts2, ts1) == 1
    end
  end
end
