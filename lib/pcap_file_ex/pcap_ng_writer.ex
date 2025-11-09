defmodule PcapFileEx.PcapNgWriter do
  @moduledoc """
  PCAPNG file writer module.

  Provides functions to create PCAPNG files with multiple interfaces and write packets.

  ## Examples

      # Create a new PCAPNG file
      {:ok, writer} = PcapFileEx.PcapNgWriter.open("output.pcapng", endianness: "little")

      # Register interfaces
      interface = %PcapFileEx.Interface{
        id: 0,
        linktype: "ethernet",
        snaplen: 65535,
        name: "eth0",
        description: "Ethernet interface",
        timestamp_resolution: "microsecond",
        timestamp_resolution_raw: "microsecond",
        timestamp_offset_secs: 0
      }

      {:ok, 0} = PcapFileEx.PcapNgWriter.write_interface(writer, interface)

      # Write packets (must have interface_id set)
      packet_with_iface = %{packet | interface_id: 0}
      :ok = PcapFileEx.PcapNgWriter.write_packet(writer, packet_with_iface)

      # Close when done
      :ok = PcapFileEx.PcapNgWriter.close(writer)

  ## Limitations

  - **Append mode not yet implemented**: PCAPNG append requires scanning for the
    last packet block and truncating trailing metadata. This will be added in a
    future version. Create new files for now.
  - **Interface validation**: All packets must reference a registered interface ID.
  - **Thread safety**: Each writer instance should be used from a single process.

  For batch writes with automatic interface registration, see `write_all/3`.
  """

  alias PcapFileEx.{Interface, Native, Packet}

  @type t :: %__MODULE__{
          reference: reference(),
          path: String.t()
        }

  defstruct [:reference, :path]

  @doc """
  Opens a new PCAPNG file for writing.

  Creates the file and writes the section header block.

  ## Options

    * `:endianness` - Byte order for the file ("big" or "little", default: "little")

  ## Returns

    * `{:ok, writer}` - Writer handle for subsequent operations
    * `{:error, reason}` - File creation failed

  ## Examples

      {:ok, writer} = PcapFileEx.PcapNgWriter.open("output.pcapng")
      {:ok, writer} = PcapFileEx.PcapNgWriter.open("output.pcapng", endianness: "big")
  """
  @spec open(Path.t(), keyword()) :: {:ok, t()} | {:error, String.t()}
  def open(path, opts \\ []) when is_binary(path) do
    endianness = Keyword.get(opts, :endianness, "little")

    case Native.pcapng_writer_open(path, endianness) do
      {:error, reason} ->
        {:error, reason}

      reference when is_reference(reference) ->
        {:ok,
         %__MODULE__{
           reference: reference,
           path: path
         }}
    end
  end

  @doc """
  Opens a new PCAPNG file for writing, raising on error.

  See `open/2` for details.

  ## Examples

      writer = PcapFileEx.PcapNgWriter.open!("output.pcapng")
  """
  @spec open!(Path.t(), keyword()) :: t()
  def open!(path, opts \\ []) do
    case open(path, opts) do
      {:ok, writer} -> writer
      {:error, reason} -> raise "Failed to open PCAPNG writer: #{reason}"
    end
  end

  @doc """
  Opens an existing PCAPNG file for appending (NOT YET IMPLEMENTED).

  PCAPNG append mode requires scanning for the last packet block and
  truncating trailing metadata blocks. This will be implemented in a
  future version.

  ## Returns

    * `{:error, reason}` - Always returns error explaining limitation
  """
  @spec append(Path.t()) :: {:error, String.t()}
  def append(path) when is_binary(path) do
    Native.pcapng_writer_append(path)
  end

  @doc """
  Registers an interface with the PCAPNG writer.

  Must be called before writing any packets that reference this interface.
  The returned interface ID should be used when writing packets.

  ## Parameters

    * `writer` - Writer handle from `open/1`
    * `interface` - Interface descriptor

  ## Returns

    * `{:ok, interface_id}` - Interface registered with this ID
    * `{:error, reason}` - Registration failed

  ## Examples

      interface = %PcapFileEx.Interface{
        id: 0,  # This will be ignored, actual ID returned
        linktype: "ethernet",
        snaplen: 65535,
        timestamp_resolution_raw: "microsecond"
      }

      {:ok, id} = PcapFileEx.PcapNgWriter.write_interface(writer, interface)
      # Use `id` when writing packets for this interface
  """
  @spec write_interface(t(), Interface.t()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def write_interface(%__MODULE__{reference: ref}, %Interface{} = interface) do
    interface_map = Interface.to_map(interface)

    case Native.pcapng_writer_write_interface(ref, interface_map) do
      id when is_integer(id) -> {:ok, id}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Writes a single packet to the PCAPNG file.

  The packet must have its `interface_id` field set to a registered interface.

  ## Parameters

    * `writer` - Writer handle from `open/1`
    * `packet` - Packet struct with `interface_id` set

  ## Returns

    * `:ok` - Packet written successfully
    * `{:error, reason}` - Write failed (e.g., invalid interface_id)

  ## Examples

      packet_with_iface = %{packet | interface_id: 0}
      :ok = PcapFileEx.PcapNgWriter.write_packet(writer, packet_with_iface)
  """
  @spec write_packet(t(), Packet.t()) :: :ok | {:error, String.t()}
  def write_packet(%__MODULE__{reference: ref}, %Packet{} = packet) do
    if is_nil(packet.interface_id) do
      {:error, "Packet must have interface_id set for PCAPNG format"}
    else
      packet_map = Packet.to_map(packet)
      Native.pcapng_writer_write_packet(ref, packet_map)
    end
  end

  @doc """
  Writes all packets from an enumerable to a new PCAPNG file.

  Convenience function that:
  1. Opens a new file
  2. Registers all provided interfaces
  3. Writes all packets
  4. Closes the file

  ## Parameters

    * `path` - Path to the PCAPNG file to create
    * `interfaces` - List of interface descriptors to register
    * `packets` - Enumerable of `Packet` structs (must have interface_id set)

  ## Options

    * `:endianness` - Byte order ("big" or "little", default: "little")

  ## Returns

    * `{:ok, count}` - Number of packets written
    * `{:error, reason}` - Operation failed

  ## Examples

      interfaces = [%PcapFileEx.Interface{linktype: "ethernet", ...}]
      packets = [%Packet{interface_id: 0, ...}, ...]

      {:ok, 100} = PcapFileEx.PcapNgWriter.write_all(
        "output.pcapng",
        interfaces,
        packets
      )
  """
  @spec write_all(Path.t(), [Interface.t()], Enumerable.t(), keyword()) ::
          {:ok, non_neg_integer()} | {:error, String.t()}
  def write_all(path, interfaces, packets, opts \\ []) when is_list(interfaces) do
    with {:ok, writer} <- open(path, opts),
         {:ok, _ids} <- register_interfaces(writer, interfaces) do
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
  Closes the PCAPNG writer and flushes any buffered data.

  After calling this function, the writer handle should not be used again.

  ## Parameters

    * `writer` - Writer handle from `open/1`

  ## Returns

    * `:ok` - Writer closed successfully
    * `{:error, reason}` - Close failed

  ## Examples

      :ok = PcapFileEx.PcapNgWriter.close(writer)
  """
  @spec close(t()) :: :ok | {:error, String.t()}
  def close(%__MODULE__{reference: ref}) do
    Native.pcapng_writer_close(ref)
  end

  # Private helper to register all interfaces
  defp register_interfaces(writer, interfaces) do
    interfaces
    |> Enum.reduce_while({:ok, []}, fn interface, {:ok, ids} ->
      case write_interface(writer, interface) do
        {:ok, id} -> {:cont, {:ok, [id | ids]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, ids} -> {:ok, Enum.reverse(ids)}
      error -> error
    end
  end
end
