defmodule PcapFileEx.Format do
  @moduledoc """
  File format detection for PCAP and PCAPNG files.

  This module provides unified format detection by reading the magic number
  (first 4 bytes) from packet capture files.

  ## Supported Formats

  - **PCAP** (microsecond precision): Little-endian and big-endian
  - **PCAP** (nanosecond precision): Little-endian and big-endian
  - **PCAPNG**: Next-generation packet capture format

  ## Examples

      # Detect file format
      PcapFileEx.Format.detect("capture.pcap")
      #=> :pcap

      PcapFileEx.Format.detect("capture.pcapng")
      #=> :pcapng

      # Handle errors
      PcapFileEx.Format.detect("nonexistent.pcap")
      #=> {:error, "Cannot open file: no such file or directory"}

      PcapFileEx.Format.detect("empty.pcap")
      #=> {:error, "File is empty"}
  """

  # PCAP magic numbers - microsecond precision
  @pcap_magic_le_usec <<0xD4, 0xC3, 0xB2, 0xA1>>
  @pcap_magic_be_usec <<0xA1, 0xB2, 0xC3, 0xD4>>

  # PCAP magic numbers - nanosecond precision
  @pcap_magic_le_nsec <<0x4D, 0x3C, 0xB2, 0xA1>>
  @pcap_magic_be_nsec <<0xA1, 0xB2, 0x3C, 0x4D>>

  # PCAPNG magic number
  @pcapng_magic <<0x0A, 0x0D, 0x0D, 0x0A>>

  @doc """
  Detects the format of a packet capture file by reading its magic number.

  ## Parameters

    * `path` - Path to the packet capture file

  ## Returns

    * `:pcap` - File is in PCAP format (microsecond or nanosecond precision)
    * `:pcapng` - File is in PCAPNG format
    * `{:error, reason}` - File cannot be read or has unknown format

  ## Examples

      iex> PcapFileEx.Format.detect("test/fixtures/http.pcap")
      :pcap

      iex> PcapFileEx.Format.detect("test/fixtures/dns.pcapng")
      :pcapng

      iex> PcapFileEx.Format.detect("nonexistent.pcap")
      {:error, "Cannot open file: no such file or directory"}
  """
  @spec detect(Path.t()) :: :pcap | :pcapng | {:error, String.t()}
  def detect(path) do
    case File.open(path, [:read, :binary]) do
      {:ok, file} ->
        result =
          case IO.binread(file, 4) do
            @pcap_magic_le_usec ->
              :pcap

            @pcap_magic_be_usec ->
              :pcap

            @pcap_magic_le_nsec ->
              :pcap

            @pcap_magic_be_nsec ->
              :pcap

            @pcapng_magic ->
              :pcapng

            magic when is_binary(magic) ->
              {:error, "Unknown file format (magic: #{inspect(magic)})"}

            :eof ->
              {:error, "File is empty"}
          end

        File.close(file)
        result

      {:error, reason} ->
        {:error, "Cannot open file: #{:file.format_error(reason)}"}
    end
  end
end
