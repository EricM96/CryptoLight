import CryptoLight

def main():
    CryptoLight.generateKey()
    plaintext = b'Hello World!'
    CryptoLight.encrypt(plaintext)
    print(plaintext)
    
if __name__ == "__main__":
    main() 