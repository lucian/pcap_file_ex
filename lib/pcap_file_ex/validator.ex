defmodule PcapFileEx.Validator do
  @moduledoc """
  File validation helpers for PCAP and PCAPNG files.
  """

  @pcap_magic_le <<0xD4, 0xC3, 0xB2, 0xA1>>
  @pcap_magic_be <<0xA1, 0xB2, 0xC3, 0xD4>>
  @pcapng_magic <<0x0A, 0x0D, 0x0D, 0x0A>>

  @doc """
  Validates if a file is a valid PCAP or PCAPNG file.

  ## Returns

  - `{:ok, :pcap}` - Valid PCAP file
  - `{:ok, :pcapng}` - Valid PCAPNG file
  - `{:error, reason}` - Invalid or inaccessible file

  ## Examples

      iex> PcapFileEx.Validator.validate("capture.pcap")
      {:ok, :pcap}

      iex> PcapFileEx.Validator.validate("capture.pcapng")
      {:ok, :pcapng}

      iex> PcapFileEx.Validator.validate("not_a_capture.txt")
      {:error, "Unknown file format"}
  """
  @spec validate(Path.t()) :: {:ok, :pcap | :pcapng} | {:error, String.t()}
  def validate(path) when is_binary(path) do
    case detect_format(path) do
      :pcap -> {:ok, :pcap}
      :pcapng -> {:ok, :pcapng}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Checks if a file is a valid PCAP file.

  ## Examples

      iex> PcapFileEx.Validator.pcap?("capture.pcap")
      true

      iex> PcapFileEx.Validator.pcap?("capture.pcapng")
      false
  """
  @spec pcap?(Path.t()) :: boolean()
  def pcap?(path) when is_binary(path) do
    case validate(path) do
      {:ok, :pcap} -> true
      _ -> false
    end
  end

  @doc """
  Checks if a file is a valid PCAPNG file.

  ## Examples

      iex> PcapFileEx.Validator.pcapng?("capture.pcapng")
      true

      iex> PcapFileEx.Validator.pcapng?("capture.pcap")
      false
  """
  @spec pcapng?(Path.t()) :: boolean()
  def pcapng?(path) when is_binary(path) do
    case validate(path) do
      {:ok, :pcapng} -> true
      _ -> false
    end
  end

  @doc """
  Checks if a file exists and is readable.

  ## Examples

      iex> PcapFileEx.Validator.readable?("capture.pcap")
      true

      iex> PcapFileEx.Validator.readable?("nonexistent.pcap")
      false
  """
  @spec readable?(Path.t()) :: boolean()
  def readable?(path) when is_binary(path) do
    case File.stat(path) do
      {:ok, %File.Stat{access: access}} when access in [:read, :read_write] -> true
      _ -> false
    end
  end

  @doc """
  Gets file size in bytes.

  ## Examples

      iex> PcapFileEx.Validator.file_size("capture.pcap")
      {:ok, 1024}

      iex> PcapFileEx.Validator.file_size("nonexistent.pcap")
      {:error, :enoent}
  """
  @spec file_size(Path.t()) :: {:ok, non_neg_integer()} | {:error, File.posix()}
  def file_size(path) when is_binary(path) do
    case File.stat(path) do
      {:ok, %File.Stat{size: size}} -> {:ok, size}
      {:error, reason} -> {:error, reason}
    end
  end

  # Private functions

  @spec detect_format(Path.t()) :: :pcap | :pcapng | {:error, String.t()}
  defp detect_format(path) do
    case File.open(path, [:read, :binary]) do
      {:ok, file} ->
        result =
          case IO.binread(file, 4) do
            @pcap_magic_le ->
              :pcap

            @pcap_magic_be ->
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
