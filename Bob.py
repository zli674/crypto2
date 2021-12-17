
# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

# Reading material: https://stackoverflow.com/questions/51228645/how-can-i-encrypt-with-a-rsa-private-key-in-python/51230724


# This is an encryption program written for alice to share her public key
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import base64
import os


def RSA_generate_keys():
    # Generate the private key
    # https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
    private_key = RSA.generate(2048)

    # Generate the public key
    public_key = private_key.publickey()

    # Export public key
    f1 = open('RSA_publickey.pem', 'wb')
    f1.write(public_key.export_key('PEM'))
    f1.close()

    return private_key


def RSA_encrypt_public_key(a_message):
    # Read the received public key file
    f1 = open('RSA_publickey.pem', 'rb')
    public_key = RSA.import_key(f1.read())
    f1.close()

    # Encrypt with public key
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted_msg = encryptor.encrypt(a_message)

    # Encode as base64
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)

    # Save the encrypted message as file
    f2 = open('Encrypted_AESkey.txt', 'wb')
    f2.write(encoded_encrypted_msg)
    f2.close()

    return encoded_encrypted_msg


def RSA_decrypt_private_key(private_key):
    # Read encrypted message from file
    f1 = open('Encrypted_AESkey.txt', 'rb')
    encoded_encrypted_msg = f1.read()
    f1.close()

    # Decrypt received message
    encryptor = PKCS1_OAEP.new(private_key)
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)

    # Decode received message
    decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)

    return decoded_decrypted_msg


def AES_keygen():
    # https://stackoverflow.com/questions/20936993/how-can-i-create-a-random-number-that-is-cryptographically-secure-in-python
    # 256-bit key
    return os.urandom(32)


def Alice_RSA_start():
    # Generate public/private key for key sharing
    return RSA_generate_keys()


def Bob_AES_key_gen_send():
    # Generate AES key
    aes_key = AES_keygen()

    # Share AES key to Alice using RSA
    RSA_encrypt_public_key(aes_key)

    # Return AES key for testing
    return aes_key


def Alice_get_AES_key(private_key):
    # decrypt the AES key sent by Bob
    return RSA_decrypt_private_key(private_key)


def AES_encrypt(aes_key, message):
    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
    # Encrypt data with AES
    cipher = AES.new(aes_key, AES.MODE_EAX)
    # Nonce is a number that can be only used once!
    nonce = cipher.nonce
    data = message.encode('UTF-8')
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Export AES ciphertext
    f1 = open('AES_ciphertext.txt', 'wb')
    f1.write(ciphertext)
    f1.close()

    # Export AES tag
    f2 = open('AES_tag.txt', 'wb')
    f2.write(tag)
    f2.close()

    # Export Nonce
    f3 = open('AES_nonce.txt', 'wb')
    f3.write(nonce)
    f3.close()


def AES_decrypt(aes_key):
    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
    # Decrypt data with AES

    # Read AES ciphertext
    f1 = open('AES_ciphertext.txt', 'rb')
    ciphertext = f1.read()
    f1.close()

    # Read AES tag
    f2 = open('AES_tag.txt', 'rb')
    tag = f2.read()
    f2.close()

    # Read Nonce
    f3 = open('AES_nonce.txt', 'rb')
    nonce = f3.read()
    f3.close()

    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("The message is authentic:", plaintext)
        return plaintext
    except ValueError:
        print("Key incorrect or message corrupted")


def main():
    # Only Alice can know private key!!!

    # Bob generate the AES key, encrypt it using the public key and send it back
    print("Press enter after receiving RSA key")
    input()
    aes_key = Bob_AES_key_gen_send()
    print("Send the new encrypted AES key to Alice")

    # Encrypt or decrypt?
    print("Enter E for encrypt, D for decrypt")
    choice = input()

    # Encrypt option
    if choice == "E":
        # Read data file
        f1 = open('data.txt', 'r')
        data = f1.read()
        f1.close()
        AES_encrypt(aes_key, data)

    # Decrypt option
    if choice == "D":
        text = AES_decrypt(aes_key)

        # Print to file
        f1 = open('data_recv.txt', 'w')
        f1.write(str(text))
        f1.close()

    print("All done. Remember to save any data_recv.txt file as they are not otherwise recoverable")


if __name__ == "__main__":
    main()
