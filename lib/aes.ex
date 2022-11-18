defmodule AES do
  # AES-GCM 128 bit
  @mode :aes_128_gcm
  @encryption_key_size 16
  @iv_size 16
  @salt_size 16
  @password_hash_position 45
  @password_hash_rounds 160000
  @aad "AES_128_GCM"

  def get_pass_hash(password, salt) do
    Pbkdf2.Base.hash_password(password, salt, rounds: @password_hash_rounds, length: @encryption_key_size)
  end

  def generate_salt do
    :crypto.strong_rand_bytes(@salt_size)
  end

  def generate_secret(hash) do
    :binary.part(hash, @password_hash_position, @encryption_key_size)
  end

  def encrypt(plaintext, secret_key) do
    iv = :crypto.strong_rand_bytes(@iv_size)
    {encrypted_text, cipher_tag} = :crypto.crypto_one_time_aead(@mode, secret_key, iv, plaintext, @aad, true)
    encrypted_text = ( iv <>  encrypted_text )
    {encrypted_text, cipher_tag}
  end

  def decrypt(ciphertext, ciphertag, secret_key) do
    <<iv::binary-@iv_size, ciphertext::binary>> = ciphertext
    try do
      :crypto.crypto_one_time_aead(@mode, secret_key, iv, ciphertext, @aad, ciphertag, false)
    rescue
      ErlangError -> raise AES.AuthenticationError
    end
  end
end
