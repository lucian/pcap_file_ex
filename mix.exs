defmodule PcapFileEx.MixProject do
  use Mix.Project

  @version "0.3.0-dev"
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
      aliases: aliases()
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
      "rust.lint": [
        "cmd cargo clippy --manifest-path=native/pcap_file_ex/Cargo.toml -- -Dwarnings"
      ],
      "rust.fmt": ["cmd cargo fmt --manifest-path=native/pcap_file_ex/Cargo.toml --all"],
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
      {:igniter, "~> 0.7.0"},
      {:stream_data, "~> 1.2", only: [:dev, :test], runtime: false},
      {:tidewave, "~> 0.5.1", only: :dev},
      {:bandit, "~> 1.0", only: :dev},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
