defmodule AESTest do
  use ExUnit.Case
  doctest AES

  test "ciphertext will decrypt to the original plaintext" do
    salt = AES.generate_salt()
    hash = AES.get_pass_hash("fakePassword", salt)
    secret = AES.generate_secret(hash)
    original_plaintext = "This is a random message to encrypt"
    ciphertext = AES.encrypt(original_plaintext, secret)
    hash = AES.get_pass_hash("fakePassword", salt)
    secret = AES.generate_secret(hash)
    plaintext = AES.decrypt(ciphertext, secret)
    assert original_plaintext == plaintext 
  end
end

