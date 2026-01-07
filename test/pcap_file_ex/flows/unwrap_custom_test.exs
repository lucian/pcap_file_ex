defmodule PcapFileEx.Flows.UnwrapCustomTest do
  @moduledoc """
  Tests for the unwrap_custom option in PcapFileEx.Flows.analyze/2.

  This option controls whether custom decoder results are returned directly
  or wrapped in {:custom, ...} tuples.
  """
  use ExUnit.Case, async: true

  alias PcapFileEx.Flows
  alias PcapFileEx.Flows.AnalysisResult

  describe "unwrap_custom option" do
    test "unwrap_custom: true is accepted" do
      {:ok, result} = Flows.analyze_segments([], [], unwrap_custom: true)
      assert %AnalysisResult{} = result
    end

    test "unwrap_custom: false is accepted" do
      {:ok, result} = Flows.analyze_segments([], [], unwrap_custom: false)
      assert %AnalysisResult{} = result
    end

    test "default is unwrap_custom: true (option is optional)" do
      {:ok, result} = Flows.analyze_segments([], [], [])
      assert %AnalysisResult{} = result
    end
  end
end
