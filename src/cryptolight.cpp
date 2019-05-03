#include <Python.h>
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

using namespace CryptoPP;
AutoSeededRandomPool rng;

int cGenerateKey(void) {
    SecByteBlock key(SPECK128::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(key, key.size());

    ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));

    return 0;
}

std::string cEncrypt(char *plain_text) {
    std::string cipher_text, iv_string;
    // read key from file
    SecByteBlock key(SPECK128::DEFAULT_KEYLENGTH);
    FileSource("key.bin", true, new ArraySink(key.begin(), key.size()));

    // Create IV for encryption 
    byte iv[SPECK128::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    StringSource(iv, sizeof(iv), true, new HexEncoder(
                            new StringSink(iv_string)));

    CBC_Mode<SPECK128>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    StringSource(plain_text, true, new StreamTransformationFilter(e, 
                                            new StringSink(cipher_text)));

    std::string aggregate_string = iv_string + cipher_text;

    return aggregate_string;
}

std::string cDecrypt(std::string aggregate_str) {
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

static PyObject *generateKey(PyObject *self, PyObject *args) {
    int result = cGenerateKey();
    return Py_BuildValue("i", result);
}

static PyObject *encrypt(PyObject *self, PyObject *args) {
    char *msg;
    PyObject *result;
    if (!PyArg_ParseTuple(args, "y", &msg)) {
        return NULL;
    } else {
        std::string cipher_text = cEncrypt(msg);
        result = PyBytes_FromStringAndSize(cipher_text.c_str(), cipher_text.size());
        return result;
    }
}

static PyObject *decrypt(PyObject *self, PyObject *args) {
    PyObject* msg;
    const char *cipher_text;
    PyObject *result;
    if (!PyArg_ParseTuple(args, "S", &msg)) {
        return NULL;
    } else {
        cipher_text = PyBytes_AsString(msg);
        std::string plain_text = cDecrypt(cipher_text);
        result = PyBytes_FromStringAndSize(plain_text.c_str(), plain_text.size());
        return result;
    }
}

static PyMethodDef CryptoLightMethods[] = {
    {"generateKey", generateKey, METH_NOARGS, "Generates key for encryption and stores it in a file"},
    {"encrypt", encrypt, METH_VARARGS, "Encrypts bytestring"},
    {"decrypt", decrypt, METH_VARARGS, "Decrypts bytestring"},
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