"""
@Author: Eric McCullough
@Description: The C/Python API allows for the exporting of functions, but exporting
objects can be very difficult. To bypass this, this file provides a Python object
oriented interface for the functions contained in cryptolight.cpp
"""

import CryptoLightFunctions
import random, string, time, sys

from base64 import b64encode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

class CryptoLight(object):
    def __init__(self, mode):
        """
        @Params: mode -> Simon or Speck. Encryption functions are configured 
        accordingly
        """
        CryptoLightFunctions.generateKey()
        if mode == "Simon":
            self.encrypt_function = CryptoLightFunctions.simonEncrypt
            self.decrypt_function = CryptoLightFunctions.simonDecrypt
        elif mode == "Speck":
            self.encrypt_function = CryptoLightFunctions.speckEncrypt
            self.decrypt_function = CryptoLightFunctions.speckDecrypt

    def encrypt(self, plaintext):
        """
        @Params: plaintext -> plaintext to encrypt
        @Description: encryption within the C++ module can lead to a bytestring
        containing a null byte. This breaks the C/Python API's ability to pass 
        the resulting bytestring to the C++ module's decryption function. To bypass
        this, the encryption function is set in a while loop until no null bytes
        are within the the ciphertext. 
        """
        ciphertext = self.encrypt_function(plaintext)
        while b'\x00' in ciphertext:
            ciphertext = self.encrypt_function(plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        return self.decrypt_function(ciphertext)

class AES_Crypt(object):
    def __init__(self):
        self.key = get_random_bytes(16)

    def encrypt(self, msg):
        msg = pad(msg, AES.block_size)
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv, cipher.encrypt(msg) 

    def decrypt(self, iv, msg):
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(msg), AES.block_size)


def test():
    while True:
        c = CryptoLight(sys.argv[1])
        letters = string.ascii_lowercase
        plaintext = ''.join(random.choice(letters) for i in range(100)).encode()
        print(plaintext)
        ciphertext = c.encrypt(plaintext)
        print(ciphertext)
        try:
            recovered_plaintext = c.decrypt(ciphertext)
        except:
            break
        print(recovered_plaintext)
        time.sleep(1)

def main():
    # c = CryptoLight("Simon")

    c = AES_Crypt()

    fin = open("test_file_pt.txt", "rb")
    fout1 = open("test_file_ct.txt", "wb")
    fout2 = open("test_file_rpt.txt", "wb")
    data = fin.read() 

    # start = time.time()
    # for i in range(0, len(data), 100):
    #     ct = c.encrypt(data[i:i+100])
    #     fout1.write(ct)
    #     rpt = c.decrypt(ct)
    #     fout2.write(rpt)
    # end = time.time()
    # print("Speck Time: ", end - start)

    start = time.time()
    for i in range(0, len(data), 100):
        iv, ct = c.encrypt(data[i:i+100])
        fout1.write(ct)
        rpt = c.decrypt(iv, ct)
        fout2.write(rpt)
    end = time.time()
    print("AES Time: ", end-start)


    fin.close()
    fout1.close()
    fout2.close()


if __name__ == "__main__":
    main()
