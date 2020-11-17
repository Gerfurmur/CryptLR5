import auth_encryptor




def main():
    with open("books.txt") as readfile:
        data = (readfile.read()).encode()
    enc = auth_encryptor.auth_encryptor("encryption")
    enc.set_key(b"key of len 16 bt", b"another key 16bt")
    iv = b"1000000000000000"
    encrypted_data_mac = enc.process_data(data, iv)
    print("encrypted data + mac =", encrypted_data_mac)

    dec = auth_encryptor.auth_encryptor("decryption")
    dec.set_key(b"key of len 16 bt", b"another key 16bt")
    decrypted_data = dec.process_data(encrypted_data_mac)
    print("decrypted data =", decrypted_data)
    print(dec.process_data(encrypted_data_mac[:-1]))


if __name__ == "__main__":
    main()