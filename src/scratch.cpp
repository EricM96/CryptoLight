#include <iostream> 
#include <string>

#include "cryptopp/modes.h"
#include "cryptopp/speck.h"
#include "cryptopp/filters.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"

// UNABLE TO BUILD TRY DIFFERENT DIRECTORY

int cEncrypt(char *msg) {
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::SecByteBlock key(CryptoPP::SPECK128::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    CryptoPP::byte iv[CryptoPP::SPECK128::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    std::cout << "Key: ";
    CryptoPP::StringSource(key, key.size(), true,
                           new CryptoPP::HexEncoder(new CryptoPP::FileSink(
                               std::cout)));
    std::cout << std::endl;

    std::cout << "IV: ";
    CryptoPP::StringSource(iv, sizeof(iv), true, new CryptoPP::HexEncoder(
                            new CryptoPP::FileSink(std::cout)));
    std::cout << std::endl;
    std::string cipher, encoded, recovered;
    std::cout << "plain text: " << msg << std::endl;

    CryptoPP::CBC_Mode<CryptoPP::SPECK128>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    CryptoPP::StringSource(msg, true,
        new CryptoPP::StreamTransformationFilter(e,
        new CryptoPP::StringSink(cipher)) // StreamTransformationFilter
    );     // StringSource
    std::cout << msg << "\n";

    std::cout << "Cipher text: ";
    CryptoPP::StringSource(cipher, true, new CryptoPP::HexEncoder(
        new CryptoPP::FileSink(std::cout)));
    std::cout << std::endl;

    return 0;
}

int main(void) {
    char *msg = "Hello World!";
    cEncrypt(msg); 

    return 0;
}