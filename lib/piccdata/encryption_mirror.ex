defmodule Ntag424.PiccData.EncryptionMirror do
  @doc """
  Module for decrypting SUN messages and calculating SDMMAC from NTAG 424 DNA\n
  """
  use Bitwise, only_operators: true

  defguard is_mod(x, y) when rem(byte_size(x), y) == 0
  defguard both_binary(pkey, data) when is_binary(pkey) and is_binary(data)
  defguard dsm_guard(mk, fk, data, cmac) when both_binary(mk, fk) and both_binary(data, cmac)

  @ntag_head <<0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80>>
  # 16 byte or 128 bit
  @aes_block_size 16
  # Initialization vector
  @iv <<0::128>>

  @doc """
  Calculates SDMMAC for `file_read_key` and `picc_data`\n
  File read key is secret (AES key) 128bit|256bit depending on tag capability.\n
  Picc data is data you get from NTAG (from URL where it is base16 encoded)
  """
  @spec calculate_sdmmac(binary(), binary()) :: binary()
  def calculate_sdmmac(file_read_key, picc_data) when both_binary(file_read_key, picc_data) do
    binary_stream = @ntag_head <> picc_data

    # Padding binary represented tag data is required in
    # order to work with aes. AES block size is 128 bit
    padded_binary_stream = binary_stream |> pad_binary()

    cmac_one =
      :crypto.mac_init(:cmac, :aes_128_cbc, file_read_key)
      |> :crypto.mac_update(padded_binary_stream)
      |> :crypto.mac_final()

    <<_::binary-size(1)>> <> cmac_two =
      :crypto.mac_init(:cmac, :aes_128_cbc, cmac_one)
      |> :crypto.mac_final()

    cmac_two
    |> :erlang.binary_to_list()
    |> Enum.take_every(2)
    |> :erlang.list_to_binary()
  end

  @doc """
  Decrypt SUN message
  """

  @spec decrypt_sun_message(binary(), binary(), binary(), binary()) :: {:ok, integer()} | {:error, String.t()}
  def decrypt_sun_message(meta_key, file_key, data, cmac) when dsm_guard(meta_key, file_key, data, cmac) do
    pstream = :crypto.crypto_one_time(:aes_128_cbc, meta_key, @iv, data, false)
    <<tag::binary-size(1)>> <> _ = pstream
    uid_len = tag |> band(<<0x0F>>)

    with {:ok, _} <- check_length(uid_len, file_key),
         data <- check_t80({uid_len, pstream, band(tag, <<0x80>>)}),
         {data, counter} <- check_t40({uid_len, {data, pstream}, band(tag, <<0x40>>)}) do
      if calculate_sdmmac(file_key, data) == cmac,
        do: {:ok, counter},
        else: {:error, "Cmac check failed"}
    else
      {:error, "Unsupported UID length"} -> {:error, "Unsupported UID length"}
      {:error, "Bad t80"} -> {:error, "Bad t80"}
      {:error, "Bad t40"} -> {:error, "Bad t40"}
    end
  end

  defp check_t40({uid_len, {data, pstream}, t40}) when t40 == <<0x40>> do
    count = binary_part(pstream, decode_u(uid_len) + 1, 3)
    counter = :binary.decode_unsigned(count, :little)
    {data <> count, counter}
  end

  defp check_t80({uid_len, pstream, t80}) when t80 == <<0x80>>,
    do: pstream |> binary_part(1, decode_u(uid_len))

  defp check_length(uid_len, file_key) when uid_len != <<7>> do
    calculate_sdmmac(file_key, <<0::128>>)
    {:error, "Unsupported UID length"}
  end

  defp check_length(uid_len, _), do: {:ok, uid_len}

  # Helpers
  defp pad_binary(stream) when is_mod(stream, @aes_block_size), do: stream
  defp pad_binary(stream), do: pad_binary(stream <> <<0x00>>)

  defp band(x, y), do: (decode_u(x) &&& decode_u(y)) |> encode_u()

  defp decode_u(n), do: :binary.decode_unsigned(n)
  defp encode_u(n), do: :binary.encode_unsigned(n)
end
