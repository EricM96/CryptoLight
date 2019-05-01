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
    AutoSeededRandomPool prng;

    SecByteBlock key(SPECK128::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));

    return 0;
}

int cEncrypt(char *msg) {
    SecByteBlock key(SPECK128::DEFAULT_KEYLENGTH);
    FileSource fs("key.bin", true, new ArraySink(key.begin(), key.size()));

    std::cout << "Key: ";
    StringSource(key, key.size(), true,
                           new HexEncoder(new FileSink(
                               std::cout)));
    std::cout << std::endl;

    return 0;
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
        int result = cEncrypt(msg);
        return Py_BuildValue("i", result);
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