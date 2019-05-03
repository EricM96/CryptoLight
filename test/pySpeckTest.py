import CryptoLight

def main():
    CryptoLight.generateKey()
    plaintext = b'Another string againaaaaa'
    print(plaintext)
    cihpertext = CryptoLight.encrypt(plaintext)
    print(cihpertext)
    print(len(cihpertext))
    recovered_plaintext = CryptoLight.decrypt(cihpertext)
    print(recovered_plaintext)
    
if __name__ == "__main__":
    main() 