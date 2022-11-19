defmodule AES do
  # AES-GCM 128 bit
  @mode :aes_128_gcm
  @digest :sha512
  @encryption_key_size 16
  @cipher_tag_size 16
  @iv_size 16
  @salt_size 16
  @iterations 160000
  @aad "AES_128_GCM"

  def generate_secret(password, salt) do
    :crypto.pbkdf2_hmac(@digest, password, salt, @iterations, @encryption_key_size)
  end

  def generate_salt do
    :crypto.strong_rand_bytes(@salt_size)
  end

  def encrypt(plaintext, secret_key) do
    iv = :crypto.strong_rand_bytes(@iv_size)
    {encrypted_text, cipher_tag} = :crypto.crypto_one_time_aead(@mode, secret_key, iv, plaintext, @aad, true)
    encrypted_text = ( iv <>  cipher_tag <> encrypted_text )
    encrypted_text
  end

  def decrypt(ciphertext, secret_key) do
    <<iv::binary-@iv_size, ciphertag::binary-@cipher_tag_size, ciphertext::binary>> = ciphertext
    try do
      :crypto.crypto_one_time_aead(@mode, secret_key, iv, ciphertext, @aad, ciphertag, false)
    rescue
      ErlangError -> raise AES.AuthenticationError
    end
  end
end
