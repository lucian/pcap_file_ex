defmodule PcapFileEx.PcapWriter do
  @moduledoc """
  PCAP file writer module.

  Provides functions to create PCAP files and write packets to them.

  ## Examples

      # Create a new PCAP file
      header = %PcapFileEx.Header{
        version_major: 2,
        version_minor: 4,
        snaplen: 65535,
        datalink: "ethernet",
        ts_resolution: "microsecond",
        endianness: "little"
      }

      {:ok, writer} = PcapFileEx.PcapWriter.open("output.pcap", header)

      # Write packets
      :ok = PcapFileEx.PcapWriter.write_packet(writer, packet)

      # Close when done
      :ok = PcapFileEx.PcapWriter.close(writer)

  ## Limitations

  - **Append mode not supported**: The underlying pcap-file crate does not support
    appending to existing PCAP files. Use `PcapNgWriter` for append support (future).
  - **Thread safety**: Each writer instance should be used from a single process.

  For batch writes, see `write_all/3`.
  """

  alias PcapFileEx.{Header, Native, Packet}

  @type t :: %__MODULE__{
          reference: reference(),
          path: String.t(),
          header: Header.t()
        }

  defstruct [:reference, :path, :header]

  @doc """
  Opens a new PCAP file for writing.

  Creates the file and writes the PCAP header. Returns a writer handle.

  ## Parameters

    * `path` - Path to the PCAP file to create
    * `header` - PCAP header configuration

  ## Returns

    * `{:ok, writer}` - Writer handle for subsequent operations
    * `{:error, reason}` - File creation failed

  ## Examples

      header = %PcapFileEx.Header{
        version_major: 2,
        version_minor: 4,
        snaplen: 65535,
        datalink: "ethernet",
        ts_resolution: "microsecond",
        endianness: "little"
      }

      {:ok, writer} = PcapFileEx.PcapWriter.open("output.pcap", header)
  """
  @spec open(Path.t(), Header.t()) :: {:ok, t()} | {:error, String.t()}
  def open(path, %Header{} = header) when is_binary(path) do
    header_map = Header.to_map(header)

    case Native.pcap_writer_open(path, header_map) do
      {:error, reason} ->
        {:error, reason}

      reference when is_reference(reference) ->
        {:ok,
         %__MODULE__{
           reference: reference,
           path: path,
           header: header
         }}
    end
  end

  @doc """
  Opens a new PCAP file for writing, raising on error.

  See `open/2` for details.

  ## Examples

      header = %PcapFileEx.Header{...}
      writer = PcapFileEx.PcapWriter.open!("output.pcap", header)
  """
  @spec open!(Path.t(), Header.t()) :: t()
  def open!(path, %Header{} = header) do
    case open(path, header) do
      {:ok, writer} -> writer
      {:error, reason} -> raise "Failed to open PCAP writer: #{reason}"
    end
  end

  @doc """
  Opens an existing PCAP file for appending (NOT SUPPORTED).

  PCAP append mode is not supported by the pcap-file crate. This function
  always returns an error. Create a new file instead, or use PCAPNG format
  which will support append in a future version.

  ## Returns

    * `{:error, reason}` - Always returns error explaining limitation
  """
  @spec append(Path.t()) :: {:error, String.t()}
  def append(path) when is_binary(path) do
    Native.pcap_writer_append(path)
  end

  @doc """
  Writes a single packet to the PCAP file.

  The packet must have been created with the same datalink type as the
  header's datalink.

  ## Parameters

    * `writer` - Writer handle from `open/2`
    * `packet` - Packet struct to write

  ## Returns

    * `:ok` - Packet written successfully
    * `{:error, reason}` - Write failed

  ## Examples

      :ok = PcapFileEx.PcapWriter.write_packet(writer, packet)
  """
  @spec write_packet(t(), Packet.t()) :: :ok | {:error, String.t()}
  def write_packet(%__MODULE__{reference: ref}, %Packet{} = packet) do
    packet_map = Packet.to_map(packet)
    Native.pcap_writer_write_packet(ref, packet_map)
  end

  @doc """
  Writes all packets from an enumerable to a new PCAP file.

  Convenience function that opens a file, writes all packets, and closes it.

  ## Parameters

    * `path` - Path to the PCAP file to create
    * `header` - PCAP header configuration
    * `packets` - Enumerable of `Packet` structs

  ## Returns

    * `{:ok, count}` - Number of packets written
    * `{:error, reason}` - Operation failed

  ## Examples

      header = %PcapFileEx.Header{...}
      packets = [packet1, packet2, packet3]

      {:ok, 3} = PcapFileEx.PcapWriter.write_all("output.pcap", header, packets)
  """
  @spec write_all(Path.t(), Header.t(), Enumerable.t()) ::
          {:ok, non_neg_integer()} | {:error, String.t()}
  def write_all(path, %Header{} = header, packets) do
    with {:ok, writer} <- open(path, header) do
      count =
        packets
        |> Enum.reduce_while(0, fn packet, acc ->
          case write_packet(writer, packet) do
            :ok -> {:cont, acc + 1}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end)

      case close(writer) do
        :ok when is_integer(count) -> {:ok, count}
        # Propagate error from reduce_while
        :ok -> count
        {:error, reason} -> {:error, "Failed to close writer: #{reason}"}
      end
    end
  end

  @doc """
  Closes the PCAP writer and flushes any buffered data.

  After calling this function, the writer handle should not be used again.

  ## Parameters

    * `writer` - Writer handle from `open/2`

  ## Returns

    * `:ok` - Writer closed successfully
    * `{:error, reason}` - Close failed

  ## Examples

      :ok = PcapFileEx.PcapWriter.close(writer)
  """
  @spec close(t()) :: :ok | {:error, String.t()}
  def close(%__MODULE__{reference: ref}) do
    Native.pcap_writer_close(ref)
  end
end
