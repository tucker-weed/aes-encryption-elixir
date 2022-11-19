defmodule AESTest do
  use ExUnit.Case
  doctest AES

  test "ciphertext will decrypt to the original plaintext" do
    salt = AES.generate_salt()
    secret = AES.generate_secret("fakePassword", salt)
    original_plaintext = "This is a random message to encrypt"
    ciphertext = AES.encrypt(original_plaintext, secret)
    secret = AES.generate_secret("fakePassword", salt)
    plaintext = AES.decrypt(ciphertext, secret)
    assert original_plaintext == plaintext 
  end
end

