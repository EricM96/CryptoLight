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

int cGenerateKey(void) {
    // TODO add method of adding key to libraries current directory
    AutoSeededRandomPool prng;

    SecByteBlock key(SPECK128::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));

    return 0;
}

std::string cEncrypt(char *plain_text) {
    std::string cipher_text;
    // read key from file
    SecByteBlock key(SPECK128::DEFAULT_KEYLENGTH);
    FileSource fs("key.bin", true, new ArraySink(key.begin(), key.size()));

    // Create IV for encryption
    AutoSeededRandomPool rng;   //TODO: add rng to a file so you don't have to make a new one every time
    byte iv[SPECK128::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    CBC_Mode<SPECK128>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    StringSource(plain_text, true, new StreamTransformationFilter(e, 
                                            new StringSink(cipher_text)));

    return cipher_text;
}

static PyObject *generateKey(PyObject *self, PyObject *args) {
    int result = cGenerateKey();
    return Py_BuildValue("i", result);
}

static PyObject *encrypt(PyObject *self, PyObject *args) {
    char *msg;
    if (!PyArg_ParseTuple(args, "y", &msg)) {
        return NULL;
    } else {
        std::string result = cEncrypt(msg);
        return Py_BuildValue("y", result);
    }
}

static PyMethodDef CryptoLightMethods[] = {
    {"generateKey", generateKey, METH_NOARGS, "Generates key for encryption and stores it in a file"},
    {"encrypt", encrypt, METH_VARARGS, "Encrypts bytestring"},
    {NULL, NULL, 0, NULL} // Sentinel 
};

static struct PyModuleDef pySpeck = {
    PyModuleDef_HEAD_INIT,
    "CryptoLight",
    "CryptoLight",
    -1,
    CryptoLightMethods 
};

PyMODINIT_FUNC PyInit_CryptoLight(void) {
    return PyModule_Create(&pySpeck);
}