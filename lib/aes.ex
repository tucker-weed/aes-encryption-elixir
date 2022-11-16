defmodule AES do
  # AES 128 Bit cipher block chaining
  @mode :aes_128_cbc
  @block_size 16
  @password_hash_position 55
  @password_hash_rounds 160000

  def get_pass_hash(password) do
    Pbkdf2.Base.hash_password(password, generate_salt(), rounds: @password_hash_rounds)
  end

  def get_pass_hash(password, existing_salt) do
    {:ok, salt} = File.read(existing_salt)
    Pbkdf2.Base.hash_password(password, salt, rounds: @password_hash_rounds)
  end

  def generate_salt do
    salt = :crypto.strong_rand_bytes(@block_size) |> :base64.encode
    File.write("./salt", salt)
    salt
  end

  def generate_secret(password) do
    :binary.part(get_pass_hash(password), @password_hash_position, @block_size) |> :base64.encode
  end

  def generate_secret(password, existing_salt) do
    :binary.part(get_pass_hash(password, existing_salt), @password_hash_position, @block_size) |> :base64.encode
  end

  def encrypt(plaintext, key) do
    secret_key = :base64.decode(key)
    iv = :crypto.strong_rand_bytes(@block_size)
    encrypted_text = :crypto.crypto_one_time(@mode, secret_key, iv, plaintext, [{:encrypt, true}, {:padding, :pkcs_padding}])
    encrypted_text = ( iv <>  encrypted_text )
    :base64.encode(encrypted_text)
  end

  def decrypt(ciphertext, key) do
    secret_key = :base64.decode(key)
    ciphertext = :base64.decode(ciphertext)
    <<iv::binary-16, ciphertext::binary>> = ciphertext
    try do
      :crypto.crypto_one_time(@mode, secret_key, iv, ciphertext, [{:encrypt, false}, {:padding, :pkcs_padding}])
    rescue
      ErlangError -> raise AES.AuthenticationError
    end
  end
end
