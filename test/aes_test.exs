defmodule AESTest do
  use ExUnit.Case
  doctest AES

  setup do
    original_plaintext = "This is a random message to encrypt"
    %{opt1: original_plaintext}
  end

  test "ciphertext will decrypt to the original plaintext", %{opt1: original_plaintext} do
    salt = AES.generate_salt()
    secret = AES.generate_secret("fakePassword", salt)
    ciphertext = AES.encrypt(original_plaintext, secret)
    secret = AES.generate_secret("fakePassword", salt)
    plaintext = AES.decrypt(ciphertext, secret)
    assert original_plaintext == plaintext 
  end
end

