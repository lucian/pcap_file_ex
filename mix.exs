defmodule PcapFileEx.MixProject do
  use Mix.Project

  @version "0.1.1"
  @source_url "https://github.com/lucian/pcap_file_ex"

  def project do
    [
      app: :pcap_file_ex,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),

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
        "mix.exs",
        "README.md",
        "LICENSE",
        "CHANGELOG.md"
      ],
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/master/CHANGELOG.md"
      },
      maintainers: ["Lucian Parvu"]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md",
        "CHANGELOG.md"
      ],
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end

  defp aliases do
    [
      clean: ["clean", &clean_native/1]
    ]
  end

  defp clean_native(_) do
    # Clean Rust build artifacts
    File.rm_rf!("native/pcap_file_ex/target")

    # Clean compiled native libraries
    File.rm_rf!("priv")

    # Clean generated test fixtures
    File.rm("test/fixtures/new_test.pcap")
    File.rm("test/fixtures/new_test.pcapng")
    File.rm("test/fixtures/test_valid_data.pcap")
    File.rm("test/fixtures/test_valid_data.pcapng")
    File.rm("test/fixtures/linux_new_test.pcap")
    File.rm("test/fixtures/linux_new_test.pcapng")
    File.rm("test/fixtures/large_capture.pcap")
    File.rm("test/fixtures/large_capture.pcapng")
    File.rm("test/fixtures/http_load.log")
    File.rm("test/fixtures/udp_load.log")

    :ok
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:rustler, "~> 0.37.1", runtime: false},
      {:rustler_precompiled, "~> 0.8"},
      {:pkt, "~> 0.6.0"},
      {:jason, "~> 1.4", optional: true},
      {:benchee, "~> 1.3", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end
end
