defmodule Ntag424.PiccData.SdmEnc do
  @doc """
  Module for decrypting SUN messages and calculating SDMMAC from NTAG 424 DNA\n
  """
  use Bitwise, only_operators: true

  defguard is_mod(x, y) when rem(byte_size(x), y) == 0
  defguard both_binary(pkey, data) when is_binary(pkey) and is_binary(data)
  defguard dsm_guard(mk, fk, data, cmac) when both_binary(mk, fk) and both_binary(data, cmac)

  @ntag_head <<0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80>>
  @ntag_head2 <<0xC3, 0x3C, 0x00, 0x01, 0x00, 0x80>>
  # 16 byte or 128 bit
  @aes_block_size 16
  # Initialization vector
  @iv <<0::128>>
  # Sdmmac paramt text
  @spt "&sdmmac="

  def decrypt_file_data(pkey, data, count, enc_data) do
    binary_stream = @ntag_head2 <> data
    padded_binary_stream = binary_stream |> pad_binary()

    cmac_key =
      :crypto.mac_init(:cmac, :aes_128_cbc, pkey)
      |> :crypto.mac_update(padded_binary_stream)
      |> :crypto.mac_final()

    iv = :crypto.crypto_one_time(:aes_128_ecb, cmac_key, pad_counter(count), true)
    :crypto.crypto_one_time(:aes_128_cbc, cmac_key, iv, enc_data, false)
  end

  def calculate_sdmmac(bin_pkey, bin_picc_data, bin_enc_data) when both_binary(bin_pkey, bin_picc_data) do
    binary_stream = @ntag_head <> bin_picc_data
    # Padding binary represented tag data is required in
    # order to work with aes. AES block size is 128 bit
    padded_binary_stream = binary_stream |> pad_binary()
    enc = bin_enc_data |> Base.encode16()

    input_buff = (enc <> @spt) |> to_ascii()

    cmac_one =
      :crypto.mac_init(:cmac, :aes_128_cbc, bin_pkey)
      |> :crypto.mac_update(padded_binary_stream)
      |> :crypto.mac_final()

    cmac_two =
      :crypto.mac_init(:cmac, :aes_128_cbc, cmac_one)
      |> :crypto.mac_update(input_buff)
      |> :crypto.mac_final()

    cmac_two
    |> :erlang.binary_to_list()
    |> Enum.drop_every(2)
    |> :erlang.list_to_binary()
  end

  def decrypt_sun_message(meta_key, file_key, data, cmac, enc_data) when dsm_guard(meta_key, file_key, data, cmac) do
    pstream = :crypto.crypto_one_time(:aes_128_cbc, meta_key, @iv, data, false)
    <<tag::binary-size(1)>> <> _ = pstream
    uid_len = tag |> band(<<0x0F>>)

    with {:ok, _} <- check_length(uid_len, file_key),
         data <- uid_mirroring_en({uid_len, pstream, band(tag, <<0x80>>)}),
         {data, count, counter} <- sdm_read_ctr_en({uid_len, {data, pstream}, band(tag, <<0x40>>)}),
         ^cmac <- calculate_sdmmac(file_key, data, enc_data) do
      file_data = decrypt_file_data(file_key, data, count, enc_data) |> parse_enc_data()
      {counter, file_data}
    else
      {:error, "Unsupported UID length"} -> {:error, "Unsupported UID length"}
      {:error, "Bad t80"} -> {:error, "Bad t80"}
      {:error, "Bad t40"} -> {:error, "Bad t40"}
      {:error, "Cmac check failed"} -> {:error, "Cmac check failed"}
    end
  end

  defp sdm_read_ctr_en({uid_len, {data, pstream}, t40}) when t40 == <<0x40>> do
    count = binary_part(pstream, decode_u(uid_len) + 1, 3)
    counter = :binary.decode_unsigned(count, :little)
    {data <> count, count, counter}
  end

  defp uid_mirroring_en({uid_len, pstream, t80}) when t80 == <<0x80>>,
    do: pstream |> binary_part(1, decode_u(uid_len))

  defp check_length(uid_len, file_key) when uid_len != <<7>> do
    calculate_sdmmac(file_key, <<0::128>>, <<0::128>>)
    {:error, "Unsupported UID length"}
  end

  defp check_length(uid_len, _), do: {:ok, uid_len}

  # Helpers
  defp pad_binary(stream) when is_mod(stream, @aes_block_size), do: stream
  defp pad_binary(stream), do: pad_binary(stream <> <<0x00>>)

  defp band(x, y), do: (decode_u(x) &&& decode_u(y)) |> encode_u()
  defp decode_u(n), do: :binary.decode_unsigned(n)
  defp encode_u(n), do: :binary.encode_unsigned(n)

  defp pad_counter(x), do: x <> <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>

  def to_ascii(str), do: str |> String.codepoints() |> Enum.map(&:binary.first(&1)) |> :binary.list_to_bin()

  defp parse_enc_data(data), do: data |> String.replace("x", "")
end
