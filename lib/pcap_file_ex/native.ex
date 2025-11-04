defmodule PcapFileEx.Native do
  @moduledoc false
  # Private module for NIF declarations

  use Rustler, otp_app: :pcap_file_ex, crate: "pcap_file_ex"

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
