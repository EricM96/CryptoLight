import CryptoLight

def main():
    CryptoLight.generateKey()
    plaintext = b'Hello World!'
    print(plaintext)
    cihpertext = CryptoLight.encrypt(plaintext)
    print(cihpertext)
    
if __name__ == "__main__":
    main() 