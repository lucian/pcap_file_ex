defmodule Mix.Tasks.Test.Fixtures do
  @moduledoc """
  Generates test fixture files for the test suite.

  This task automatically generates PCAP and PCAPNG test fixtures
  required by the test suite. It requires dumpcap to be installed
  and properly configured for packet capture.

  ## Usage

      mix test.fixtures           # Generate only missing fixtures
      mix test.fixtures --force   # Regenerate all fixtures

  ## Options

      --force    Force regeneration of all fixtures, even if they exist

  ## Requirements

  - dumpcap (from Wireshark package)
  - Python 3
  - Proper permissions for packet capture

  See README.md for platform-specific setup instructions.
  """

  use Mix.Task

  @shortdoc "Generate test fixture files"

  @fixtures_dir "test/fixtures"
  @required_fixtures [
    "new_test.pcap",
    "new_test.pcapng"
  ]

  @impl Mix.Task
  def run(args) do
    {opts, _, _} = OptionParser.parse(args, switches: [force: :boolean])
    force = Keyword.get(opts, :force, false)

    Mix.shell().info("Checking for missing test fixtures...")

    missing = find_missing_fixtures()

    cond do
      force ->
        Mix.shell().info("Force mode: regenerating all fixtures...")
        generate_fixtures()

      Enum.empty?(missing) ->
        Mix.shell().info("✓ All test fixtures present. Nothing to generate.")
        Mix.shell().info("Use --force to regenerate anyway.")
        :ok

      true ->
        Mix.shell().info("Missing fixtures: #{Enum.join(missing, ", ")}")
        generate_fixtures()
    end
  end

  defp find_missing_fixtures do
    Enum.filter(@required_fixtures, fn fixture ->
      path = Path.join(@fixtures_dir, fixture)
      not File.exists?(path)
    end)
  end

  defp generate_fixtures do
    unless dumpcap_available?() do
      Mix.shell().error("""
      Error: dumpcap not found in PATH.

      dumpcap is required to generate test fixtures.
      Install Wireshark to get dumpcap:

      macOS:
        brew install wireshark

      Linux (Ubuntu/Debian):
        sudo apt-get install tshark
        # Setup non-root capture:
        sudo dpkg-reconfigure wireshark-common  # Select "Yes"
        sudo usermod -aG wireshark $USER
        newgrp wireshark

      Linux (Fedora/RHEL):
        sudo dnf install wireshark-cli
        sudo usermod -aG wireshark $USER

      Linux (Arch):
        sudo pacman -S wireshark-cli
        sudo usermod -aG wireshark $USER

      See README.md for complete setup instructions and troubleshooting.
      """)

      exit({:shutdown, 1})
    end

    Mix.shell().info("")
    Mix.shell().info("Generating test fixtures...")
    Mix.shell().info("This may take 30-60 seconds...")
    Mix.shell().info("")

    # Generate new_test fixtures with custom output name
    # Use bash to execute the script
    case System.cmd(
           "bash",
           ["./capture_test_traffic.sh", "--output", "new_test.pcapng", "--count", "50"],
           cd: @fixtures_dir,
           stderr_to_stdout: true
         ) do
      {output, 0} ->
        shell = Mix.shell()
        shell.info("✓ Test fixtures generated successfully")
        shell.info("")

        # Print relevant output (skip verbose capture details)
        output
        |> String.split("\n")
        |> Enum.filter(&String.contains?(&1, ["Complete", "saved", "packets"]))
        |> Enum.each(fn line -> shell.info(line) end)

        :ok

      {output, exit_code} ->
        Mix.shell().error("✗ Failed to generate fixtures (exit code: #{exit_code})")
        Mix.shell().error("")
        Mix.shell().error(output)
        Mix.shell().error("")
        Mix.shell().error("""
        Troubleshooting:
        - Ensure dumpcap has proper permissions (see README.md)
        - macOS: brew install wireshark (includes ChmodBPF)
        - Linux: Add user to wireshark group or use sudo
        - Try running manually: cd test/fixtures && ./capture_test_traffic.sh
        - Check for permission errors or missing interfaces

        For detailed help, see README.md "Troubleshooting" section.
        """)

        exit({:shutdown, 1})
    end
  end

  defp dumpcap_available? do
    case System.cmd("which", ["dumpcap"], stderr_to_stdout: true) do
      {_, 0} -> true
      _ -> false
    end
  catch
    _ -> false
  end
end
