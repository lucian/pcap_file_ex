defmodule PcapFileEx.Validator do
  @moduledoc """
  File validation helpers for PCAP and PCAPNG files.
  """

  alias PcapFileEx.Format

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
    case Format.detect(path) do
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
end
