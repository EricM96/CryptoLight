/*
 * @Author: Eric McCullough
*/

#include <Python.h>
#include <iostream> 
#include <string>

#include "cryptopp/modes.h"
#include "cryptopp/speck.h"
#include "cryptopp/simon.h"
#include "cryptopp/filters.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/files.h"

using namespace CryptoPP;
AutoSeededRandomPool rng;

int cGenerateKey(void) {
    /* @Params: None
     * @Return: None
     * @Description: Generates a encryption key and writes it to a file in the 
     * current directory of caller. This key can be extracted by the encryption
     * and decryption functions. Both encryption algorithms have the same key
     * length, so SPECK128::DEFAULT_KEYLENGTH is used for both.
    */
    SecByteBlock key(SPECK128::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());
    ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));

    return 0;
}

std::string cSpeckEncrypt(char *plain_text) {
    /* @Params: plain_text to be encrypted
     * @Return: initialization vector concatonated with encrypted plain text
     * @Description: Encrypts plain text with Cipher Blockchaining Mode. The 
     * initialization vector used to encrypt the plain text is concatonated 
     * to the front of the cipher text.
    */
    std::string cipher_text, iv_string;
    // read key from file
    SecByteBlock key(SPECK128::DEFAULT_KEYLENGTH);
    FileSource("key.bin", true, new ArraySink(key.begin(), key.size()));

    // Create IV for encryption 
    byte iv[SPECK128::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(iv_string)));

    CBC_Mode<SPECK128>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    StringSource(plain_text, true, new StreamTransformationFilter(e, 
                                            new StringSink(cipher_text)));

    std::string aggregate_string = iv_string + cipher_text;

    return aggregate_string;
}

std::string cSpeckDecrypt(std::string aggregate_str) {
    /* @Params: aggregate_str -> the IV + cipher text
     * @Return: decrypted cipher text
     * @Description: Extracts iv and plain text from the aggregate_str and decrypts
     * the cipher text
    */
    std::string plain_text;

    byte iv[SPECK128::BLOCKSIZE];
    std::string iv_string = aggregate_str.substr(0, 32);
    std::string cipher_text = aggregate_str.substr(32);

    SecByteBlock key(SPECK128::DEFAULT_KEYLENGTH);
    FileSource("key.bin", true, new ArraySink(key.begin(), key.size()));

    StringSource(iv_string, true, new HexDecoder(new ArraySink(iv, SPECK128::BLOCKSIZE)));

    CBC_Mode<SPECK128>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    StringSource(cipher_text, true, new StreamTransformationFilter(d, 
                                            new StringSink(plain_text)));

    return plain_text;
}

std::string cSimonEncrypt(char *plain_text) {
    /* @Params: plain_text to be encrypted
     * @Return: initialization vector concatonated with encrypted plain text
     * @Description: Encrypts plain text with Cipher Blockchaining Mode. The 
     * initialization vector used to encrypt the plain text is concatonated 
     * to the front of the cipher text.
    */
    std::string cipher_text, iv_string;
    // read key from file
    SecByteBlock key(SIMON128::DEFAULT_KEYLENGTH);
    FileSource("key.bin", true, new ArraySink(key.begin(), key.size()));

    // Create IV for encryption 
    byte iv[SIMON128::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(iv_string)));

    CBC_Mode<SIMON128>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    StringSource(plain_text, true, new StreamTransformationFilter(e, 
                                            new StringSink(cipher_text)));

    std::string aggregate_string = iv_string + cipher_text;

    return aggregate_string;
}

std::string cSimonDecrypt(std::string aggregate_str) {
    /* @Params: aggregate_str -> the IV + cipher text
     * @Return: decrypted cipher text
     * @Description: Extracts iv and plain text from the aggregate_str and decrypts
     * the cipher text
    */
    std::string plain_text;

    byte iv[SIMON128::BLOCKSIZE];
    std::string iv_string = aggregate_str.substr(0, 32);
    std::string cipher_text = aggregate_str.substr(32);

    SecByteBlock key(SIMON128::DEFAULT_KEYLENGTH);
    FileSource("key.bin", true, new ArraySink(key.begin(), key.size()));

    StringSource(iv_string, true, new HexDecoder(new ArraySink(iv, SIMON128::BLOCKSIZE)));

    CBC_Mode<SIMON128>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    StringSource(cipher_text, true, new StreamTransformationFilter(d, 
                                            new StringSink(plain_text)));

    return plain_text;
}

static PyObject *generateKey(PyObject *self, PyObject *args) {
    int result = cGenerateKey();
    return Py_BuildValue("i", result);
}

static PyObject *speckEncrypt(PyObject *self, PyObject *args) {
    /* @Description: Middle man function. Translates Python args to C datatypes
     * and vice versa 
    */
    char *msg;
    PyObject *result;
    if (!PyArg_ParseTuple(args, "y", &msg)) {
        return NULL;
    } else {
        std::string cipher_text = cSpeckEncrypt(msg);
        result = PyBytes_FromStringAndSize(cipher_text.c_str(), cipher_text.size());
        return result;
    }
}

static PyObject *speckDecrypt(PyObject *self, PyObject *args) {
    /* @Description: Middle man function. Translates Python args to C datatypes
     * and vice versa 
    */
    PyObject* msg;
    const char *cipher_text;
    PyObject *result;
    if (!PyArg_ParseTuple(args, "S", &msg)) {
        return NULL;
    } else {
        cipher_text = PyBytes_AsString(msg);
        std::string plain_text = cSpeckDecrypt(cipher_text);
        result = PyBytes_FromStringAndSize(plain_text.c_str(), plain_text.size());
        return result;
    }
}

static PyObject *simonEncrypt(PyObject *self, PyObject *args) {
    /* @Description: Middle man function. Translates Python args to C datatypes
     * and vice versa 
    */
    char *msg;
    PyObject *result;
    if (!PyArg_ParseTuple(args, "y", &msg)) {
        return NULL;
    } else {
        std::string cipher_text = cSimonEncrypt(msg);
        result = PyBytes_FromStringAndSize(cipher_text.c_str(), cipher_text.size());
        return result;
    }
}

static PyObject *simonDecrypt(PyObject *self, PyObject *args) {
    /* @Description: Middle man function. Translates Python args to C datatypes
     * and vice versa 
    */
    PyObject* msg;
    const char *cipher_text;
    PyObject *result;
    if (!PyArg_ParseTuple(args, "S", &msg)) {
        return NULL;
    } else {
        cipher_text = PyBytes_AsString(msg);
        std::string plain_text = cSimonDecrypt(cipher_text);
        result = PyBytes_FromStringAndSize(plain_text.c_str(), plain_text.size());
        return result;
    }
}

static PyMethodDef CryptoLightMethods[] = {
    {"generateKey", generateKey, METH_NOARGS, "Generates key for encryption and stores it in a file"},
    {"speckEncrypt", speckEncrypt, METH_VARARGS, "Encrypts bytestring"},
    {"speckDecrypt", speckDecrypt, METH_VARARGS, "Decrypts bytestring"},
    {"simonEncrypt", simonEncrypt, METH_VARARGS, "Encrypts bytestring"},
    {"simonDecrypt", simonDecrypt, METH_VARARGS, "Decrypts bytestring"},
    {NULL, NULL, 0, NULL} // Sentinel 
};

static struct PyModuleDef pySpeck = {
    PyModuleDef_HEAD_INIT,
    "CryptoLight",
    "CryptoLight",
    -1,
    CryptoLightMethods 
};

PyMODINIT_FUNC PyInit_CryptoLightFunctions(void) {
    return PyModule_Create(&pySpeck);
}