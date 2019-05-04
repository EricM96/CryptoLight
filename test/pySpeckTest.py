"""
@Author: Eric McCullough
@Description: The C/Python API allows for the exporting of functions, but exporting
objects can be very difficult. To bypass this, this file provides a Python object
oriented interface for the functions contained in cryptolight.cpp
"""

import CryptoLightFunctions
import random, string, time, sys

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


def main():
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
    
if __name__ == "__main__":
    main()
