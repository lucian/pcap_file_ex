defmodule PcapFileEx.Native do
  @moduledoc false
  # Private module for NIF declarations

  mix_config = Mix.Project.config()
  version = mix_config[:version]
  github_url = "https://github.com/lucian/pcap_file_ex"

  use RustlerPrecompiled,
    otp_app: :pcap_file_ex,
    crate: "pcap_file_ex",
    version: version,
    base_url: "#{github_url}/releases/download/v#{version}",
    targets: ~w(
      x86_64-unknown-linux-gnu
      aarch64-unknown-linux-gnu
      x86_64-apple-darwin
      aarch64-apple-darwin
      x86_64-pc-windows-msvc
      x86_64-pc-windows-gnu
    ),
    nif_versions: ["2.15"],
    force_build: System.get_env("PCAP_FILE_EX_BUILD") in ["1", "true"]

  # PCAP functions
  def pcap_open(_path), do: error()
  def pcap_close(_resource), do: error()
  def pcap_get_header(_resource), do: error()
  def pcap_next_packet(_resource), do: error()
  def pcap_set_filter(_resource, _filters), do: error()
  def pcap_clear_filter(_resource), do: error()

  # PCAPNG functions
  def pcapng_open(_path), do: error()
  def pcapng_close(_resource), do: error()
  def pcapng_interfaces(_resource), do: error()
  def pcapng_next_packet(_resource), do: error()
  def pcapng_set_filter(_resource, _filters), do: error()
  def pcapng_clear_filter(_resource), do: error()

  defp error, do: :erlang.nif_error(:nif_not_loaded)
end
