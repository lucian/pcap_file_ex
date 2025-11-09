Application.put_env(:mix, :start_pubsub, false)

# Auto-generate missing test fixtures
defmodule TestFixtureSetup do
  @fixtures_dir "test/fixtures"
  # Fixtures that cause test failures
  @critical_fixtures ["new_test.pcapng"]

  def ensure_fixtures do
    missing = find_missing_critical_fixtures()

    unless Enum.empty?(missing) do
      IO.puts("\n⚠️  Missing critical test fixtures: #{Enum.join(missing, ", ")}")
      IO.puts("Attempting to generate them automatically...\n")

      try do
        Mix.Task.run("test.fixtures")
        IO.puts("\n✓ Fixtures generated successfully\n")
      rescue
        _ ->
          IO.puts("""
          \n⚠️  Could not generate fixtures automatically.

          Some tests may be skipped. To fix:
            1. Install dumpcap (see README.md - Development Setup)
            2. Run: mix test.fixtures
            3. Or manually: cd test/fixtures && ./capture_test_traffic.sh

          See README.md "Troubleshooting" section for platform-specific help.
          """)
      end
    end
  end

  defp find_missing_critical_fixtures do
    Enum.filter(@critical_fixtures, fn fixture ->
      path = Path.join(@fixtures_dir, fixture)
      not File.exists?(path)
    end)
  end
end

TestFixtureSetup.ensure_fixtures()

# Configure property-based testing
# Use more iterations in CI for thorough testing
max_runs =
  case System.get_env("CI") do
    "true" -> 1000
    _ -> 100
  end

# Store max_runs in application env for property tests to access
Application.put_env(:stream_data, :max_runs, max_runs)

ExUnit.start()
