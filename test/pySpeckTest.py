import CryptoLight

def main():
    CryptoLight.generateKey()
    plaintext = b'Hello World!'
    print(plaintext)
    cihpertext = CryptoLight.encrypt(plaintext)
    print(cihpertext)
    print(len(cihpertext))
    CryptoLight.decrypt(cihpertext)
    
if __name__ == "__main__":
    main() 