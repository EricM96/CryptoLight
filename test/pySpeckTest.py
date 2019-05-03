import CryptoLightFunctions
import random, string, time

class CryptoLight(object):
    def __init__(self):
        CryptoLightFunctions.generateKey()

    def encrypt(self, plaintext):
        ciphertext = CryptoLightFunctions.encrypt(plaintext)
        while b'\x00' in ciphertext:
            ciphertext = CryptoLightFunctions.encrypt(plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        return CryptoLightFunctions.decrypt(ciphertext)


def main():
    while True:
        c = CryptoLight()
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
