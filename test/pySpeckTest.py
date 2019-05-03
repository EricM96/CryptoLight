import CryptoLight
import random, string

def main():
    CryptoLight.generateKey()
    letters = string.ascii_lowercase
    plaintext = ''.join(random.choice(letters) for i in range(100)).encode()
    print(plaintext)
    ciphertext = CryptoLight.encrypt(plaintext)
    while b'\x00' in ciphertext:
        print("__________error in encryption, reencrypting___________")
        ciphertext = CryptoLight.encrypt(plaintext)
    print(ciphertext)
    recovered_plaintext = CryptoLight.decrypt(ciphertext)
    print(recovered_plaintext)
    
if __name__ == "__main__":
    main() 
