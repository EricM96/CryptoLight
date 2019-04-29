import pySpeck 

def main():
    plaintext = b'Hello World!'
    pySpeck.encrypt(plaintext)
    print(plaintext)
    
if __name__ == "__main__":
    main() 