defmodule PcapFileEx.Native do
  @moduledoc false
  # Private module for NIF declarations

  mix_config = Mix.Project.config()
  version = mix_config[:version]
  github_url = "https://github.com/lucian/pcap_file_ex"

  # Check if user wants to force using legacy CPU artifacts
  use_legacy = System.get_env("PCAP_FILE_EX_USE_LEGACY_ARTIFACTS") in ["1", "true"]

  # Variant configuration for Linux x86_64: automatically detect CPU capabilities
  # and fall back to legacy_cpu variant if needed
  variants_for_linux = [
    legacy_cpu: fn ->
      needed_caps = ~w[fxsr sse sse2 sse3 ssse3 sse4.1 sse4.2 popcnt avx fma]

      use_legacy or
        (is_nil(use_legacy) and
           not PcapFileEx.ComptimeUtils.cpu_with_all_caps?(needed_caps))
    end
  ]

  # Variant configuration for other x86_64 platforms (Windows, FreeBSD):
  # only use legacy_cpu if explicitly requested via environment variable
  other_variants = [legacy_cpu: fn -> use_legacy end]

  use RustlerPrecompiled,
    otp_app: :pcap_file_ex,
    crate: "pcap_file_ex",
    version: version,
    base_url: "#{github_url}/releases/download/v#{version}",
    targets: ~w(
      aarch64-apple-darwin
      aarch64-unknown-linux-gnu
      x86_64-pc-windows-gnu
      x86_64-pc-windows-msvc
      x86_64-unknown-freebsd
      x86_64-unknown-linux-gnu
    ),
    variants: %{
      "x86_64-unknown-linux-gnu" => variants_for_linux,
      "x86_64-pc-windows-msvc" => other_variants,
      "x86_64-pc-windows-gnu" => other_variants,
      "x86_64-unknown-freebsd" => other_variants
    },
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

  # PCAP writer functions
  def pcap_writer_open(_path, _header_map), do: error()
  def pcap_writer_append(_path), do: error()
  def pcap_writer_write_packet(_resource, _packet_map), do: error()
  def pcap_writer_close(_resource), do: error()

  # PCAPNG writer functions
  def pcapng_writer_open(_path, _endianness), do: error()
  def pcapng_writer_append(_path), do: error()
  def pcapng_writer_write_interface(_resource, _interface_map), do: error()
  def pcapng_writer_write_packet(_resource, _packet_map), do: error()
  def pcapng_writer_close(_resource), do: error()

  defp error, do: :erlang.nif_error(:nif_not_loaded)
end
