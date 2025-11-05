defmodule PcapFileEx.MixProject do
  use Mix.Project

  def project do
    [
      app: :pcap_file_ex,
      version: "0.1.1",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
      {:rustler, "~> 0.37.1", runtime: false},
      {:pkt, "~> 0.6.0"},
      {:jason, "~> 1.4", optional: true},
      {:benchee, "~> 1.3", only: [:dev, :test], runtime: false}
    ]
  end
end
