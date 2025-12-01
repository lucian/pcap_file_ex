defmodule PcapFileEx.MixProject do
  use Mix.Project

  @version "0.5.1"
  @source_url "https://github.com/lucian/pcap_file_ex"
  @dev? String.ends_with?(@version, "-dev")
  @force_build? System.get_env("PCAP_FILE_EX_BUILD") in ["1", "true"]

  def project do
    [
      app: :pcap_file_ex,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),

      # Hex metadata
      description: description(),
      package: package(),

      # Docs
      docs: docs(),
      source_url: @source_url,
      homepage_url: @source_url,

      # Aliases
      aliases: aliases(),

      # Dialyzer
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/project.plt"},
        plt_add_deps: :app_tree,
        paths: ["_build/#{Mix.env()}/lib/pcap_file_ex/ebin"]
      ]
    ]
  end

  # Specifies which paths to compile per environment
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp description do
    """
    High-performance Elixir library for reading and parsing PCAP and PCAPNG
    network capture files with Rust NIF implementation.
    """
  end

  defp package do
    [
      name: "pcap_file_ex",
      files: [
        "lib",
        "native/pcap_file_ex/src",
        "native/pcap_file_ex/Cargo.toml",
        "native/pcap_file_ex/Cargo.lock",
        "checksum-*.exs",
        "mix.exs",
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "usage-rules.md",
        "usage-rules"
      ],
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/master/CHANGELOG.md",
        "Usage Rules" => "#{@source_url}/blob/master/usage-rules.md"
      },
      maintainers: ["Lucian Parvu"]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md",
        "CHANGELOG.md",
        "usage-rules.md",
        "usage-rules/performance.md",
        "usage-rules/filtering.md",
        "usage-rules/http.md",
        "usage-rules/formats.md",
        "usage-rules/examples.md",
        "LICENSE"
      ],
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end

  defp aliases do
    [
      clean: ["clean", &clean_native/1],
      setup: ["deps.get", &setup_dev_tools/1, "compile", "git_hooks.install"],
      "rust.lint": [
        "cmd cargo clippy --manifest-path=native/pcap_file_ex/Cargo.toml -- -Dwarnings"
      ],
      "rust.fmt": ["cmd cargo fmt --manifest-path=native/pcap_file_ex/Cargo.toml --all"],
      "deps.check": [&check_deps_tools/1, "hex.outdated", &check_cargo_outdated/1],
      "check.doctor": [&run_doctor_checks/1],
      ci: ["format", "rust.fmt", "rust.lint", "test"],
      tidewave:
        "run --no-halt -e 'Agent.start(fn -> Bandit.start_link(plug: Tidewave, port: 4000) end)'",
      "tidewave-iex":
        "run --no-start -e 'Application.ensure_all_started(:tidewave); {:ok, _} = Bandit.start_link(plug: Tidewave, port: 4000); IO.puts(\"Tidewave MCP server started on port 4000\")'"
    ]
  end

  defp clean_native(_) do
    # Clean Rust build artifacts
    File.rm_rf!("native/pcap_file_ex/target")

    # Clean compiled native libraries
    File.rm_rf!("priv")

    # Clean generated test fixtures
    File.rm("test/fixtures/test_valid_data.pcap")
    File.rm("test/fixtures/test_valid_data.pcapng")
    File.rm("test/fixtures/large_capture.pcap")
    File.rm("test/fixtures/large_capture.pcapng")
    File.rm("test/fixtures/http_load.log")
    File.rm("test/fixtures/udp_load.log")

    :ok
  end

  defp setup_dev_tools(_) do
    IO.puts("\n📦 Setting up development tools...")

    tools = [
      {"cargo-outdated", "cargo install --locked cargo-outdated"},
      {"cargo-deny", "cargo install --locked cargo-deny"}
    ]

    Enum.each(tools, fn {tool, install_cmd} ->
      case System.cmd("cargo", [String.replace(tool, "cargo-", ""), "--version"],
             stderr_to_stdout: true
           ) do
        {_, 0} ->
          IO.puts("  ✓ #{tool} already installed")

        _ ->
          IO.puts("  ⚙ Installing #{tool}...")

          case System.cmd("sh", ["-c", install_cmd], into: IO.stream(:stdio, :line)) do
            {_, 0} ->
              IO.puts("  ✓ #{tool} installed successfully")

            _ ->
              IO.puts("  ⚠ Failed to install #{tool}. You may need to install it manually.")
          end
      end
    end)

    IO.puts("\n✓ Setup complete! Run `mix check.doctor` to verify your environment.\n")
    :ok
  end

  defp check_deps_tools(_) do
    # This function checks if required tools are available before running deps.check
    missing = []

    missing =
      case System.cmd("cargo", ["outdated", "--version"], stderr_to_stdout: true) do
        {_, 0} -> missing
        _ -> ["cargo-outdated" | missing]
      end

    if missing != [] do
      IO.puts(:stderr, "\n❌ Missing required tools: #{Enum.join(missing, ", ")}")
      IO.puts(:stderr, "Run `mix setup` or `cargo install #{Enum.join(missing, " ")}`\n")
      exit({:shutdown, 1})
    end

    :ok
  end

  defp check_cargo_outdated(_) do
    case System.cmd(
           "cargo",
           ["outdated", "--manifest-path=native/pcap_file_ex/Cargo.toml"],
           stderr_to_stdout: true
         ) do
      {output, 0} ->
        IO.puts(output)
        :ok

      {output, _} ->
        IO.puts(output)
        IO.puts("Note: cargo-outdated check completed with warnings")
        :ok
    end
  end

  defp run_doctor_checks(_) do
    IO.puts("\n🔍 Running environment health checks...\n")

    checks = [
      check_elixir_version(),
      check_erlang_version(),
      check_rust_version(),
      check_cargo_tool("cargo-outdated"),
      check_cargo_tool("cargo-deny"),
      check_git_hooks()
    ]

    {passed, failed} =
      Enum.split_with(checks, fn {status, _, _} -> status == :ok end)

    IO.puts("\n" <> String.duplicate("─", 50))
    IO.puts("Summary: #{length(passed)} passed, #{length(failed)} failed")

    if failed != [] do
      IO.puts("\n💡 To fix missing tools, run: mix setup\n")
      exit({:shutdown, 1})
    else
      IO.puts("\n✓ All checks passed! Your environment is ready.\n")
    end

    :ok
  end

  defp check_elixir_version do
    version = System.version()
    required = "1.18.0"

    if Version.match?(version, ">= #{required}") do
      IO.puts("  ✓ Elixir #{version}")
      {:ok, :elixir, version}
    else
      IO.puts("  ✗ Elixir #{version} (>= #{required} required)")
      {:error, :elixir, version}
    end
  end

  defp check_erlang_version do
    version = :erlang.system_info(:otp_release) |> to_string()

    IO.puts("  ✓ Erlang/OTP #{version}")
    {:ok, :erlang, version}
  end

  defp check_rust_version do
    case System.cmd("cargo", ["--version"], stderr_to_stdout: true) do
      {output, 0} ->
        version = output |> String.trim() |> String.replace("cargo ", "")
        IO.puts("  ✓ Rust/Cargo #{version}")
        {:ok, :rust, version}

      _ ->
        IO.puts("  ✗ Rust/Cargo not found")
        {:error, :rust, nil}
    end
  end

  defp check_cargo_tool(tool) do
    cmd = String.replace(tool, "cargo-", "")

    case System.cmd("cargo", [cmd, "--version"], stderr_to_stdout: true) do
      {output, 0} ->
        version = output |> String.trim() |> String.split() |> Enum.at(1, "")
        IO.puts("  ✓ #{tool} #{version}")
        {:ok, String.to_atom(tool), version}

      _ ->
        IO.puts("  ✗ #{tool} not installed")
        {:error, String.to_atom(tool), nil}
    end
  end

  defp check_git_hooks do
    hook_file = ".git/hooks/pre-commit"

    if File.exists?(hook_file) do
      content = File.read!(hook_file)

      if String.contains?(content, "git_hooks") do
        IO.puts("  ✓ Git hooks installed")
        {:ok, :git_hooks, true}
      else
        IO.puts("  ⚠ Git hooks present but not from git_hooks (run mix git_hooks.install)")
        {:error, :git_hooks, false}
      end
    else
      IO.puts("  ✗ Git hooks not installed (run mix git_hooks.install)")
      {:error, :git_hooks, false}
    end
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:usage_rules, "~> 0.1", only: [:dev]},
      {:rustler, "~> 0.37.1", optional: not (@dev? or @force_build?)},
      {:rustler_precompiled, "~> 0.8"},
      {:pkt, "~> 0.6.0"},
      {:jason, "~> 1.4", optional: true},
      {:benchee, "~> 1.3", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:igniter, "~> 0.7.0", only: [:dev, :test]},
      {:stream_data, "~> 1.2", only: [:dev, :test], runtime: false},
      {:tidewave, "~> 0.5.1", only: :dev},
      {:bandit, "~> 1.0", only: :dev},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:git_hooks, "~> 0.8.1", only: [:dev], runtime: false}
    ]
  end
end
