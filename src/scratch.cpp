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

int cEncrypt(char *msg) {
    CryptoPP::AutoSeededRandomPool prng;

    CryptoPP::SecByteBlock key(CryptoPP::SPECK128::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    std::cout << "Key: ";
    CryptoPP::StringSource(key, key.size(), true,
                           new CryptoPP::HexEncoder(new CryptoPP::FileSink(
                               std::cout)));
    std::cout << std::endl;

    return 0;
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