defmodule AES do
  # AES-GCM 128 bit
  @mode :aes_128_gcm
  @encryption_key_size 16
  @iv_size 16
  @salt_size 16
  @password_hash_position 55
  @password_hash_rounds 160000
  @aad "A128GCM"

  def get_pass_hash(password) do
    Pbkdf2.Base.hash_password(password, generate_salt(), rounds: @password_hash_rounds, length: @encryption_key_size)
  end

  def get_pass_hash(password, existing_salt) do
    {:ok, salt} = File.read(existing_salt)
    Pbkdf2.Base.hash_password(password, salt, rounds: @password_hash_rounds, length: @encryption_key_size)
  end

  def generate_salt do
    salt = :crypto.strong_rand_bytes(@salt_size) |> :base64.encode
    File.write("./salt", salt)
    salt
  end

  def generate_secret(password) do
    :binary.part(get_pass_hash(password), @password_hash_position, @encryption_key_size) |> :base64.encode
  end

  def generate_secret(password, existing_salt) do
    :binary.part(get_pass_hash(password, existing_salt), @password_hash_position, @encryption_key_size) |> :base64.encode
  end

  def encrypt(plaintext, key) do
    secret_key = :base64.decode(key)
    iv = :crypto.strong_rand_bytes(@iv_size)
    {encrypted_text, cipher_tag} = :crypto.crypto_one_time_aead(@mode, secret_key, iv, plaintext, @aad, true)
    encrypted_text = ( iv <>  encrypted_text )
    {:base64.encode(encrypted_text), :base64.encode(cipher_tag)}
  end

  def decrypt(ciphertext, ciphertag, key) do
    secret_key = :base64.decode(key)
    ciphertext = :base64.decode(ciphertext)
    ciphertag = :base64.decode(ciphertag)
    <<iv::binary-@iv_size, ciphertext::binary>> = ciphertext
    try do
      :crypto.crypto_one_time_aead(@mode, secret_key, iv, ciphertext, @aad, ciphertag, false)
    rescue
      ErlangError -> raise AES.AuthenticationError
    end
  end
end
