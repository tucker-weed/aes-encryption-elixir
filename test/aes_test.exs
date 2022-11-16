defmodule AESTest do
  use ExUnit.Case
  doctest AES

  test "encrypted plaintext will decrypt to the original plaintext" do
    secret = AES.generate_secret("fakePassword")
    original_plaintext = "This is a random message to encrypt"
    {ciphertext, ciphertag} = AES.encrypt(original_plaintext, secret)
    secret = AES.generate_secret("fakePassword", "./salt")
    plaintext = AES.decrypt(ciphertext, ciphertag, secret)
    assert original_plaintext == plaintext 
  end
end

