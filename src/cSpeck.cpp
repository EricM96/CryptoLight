#include <Python.h>
#include <iostream> 
#include <string>

#include "../../speck_test/cryptopp/modes.h"
#include "../../speck_test/cryptopp/speck.h"
#include "../../speck_test/cryptopp/filters.h"
#include "../../speck_test/cryptopp/cryptlib.h"
#include "../../speck_test/cryptopp/secblock.h"
#include "../../speck_test/cryptopp/osrng.h"
#include "../../speck_test/cryptopp/hex.h"
#include "../../speck_test/cryptopp/files.h"

//int cEncrypt(Py_buffer message) {
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
    );                                                                                                // StringSource
    std::cout << msg << "\n";
    return 0;
}

static PyObject *encrypt(PyObject *self, PyObject *args) {
    //Py_buffer msg;
    char *msg;
    if (!PyArg_ParseTuple(args, "y", &msg)) {
        return NULL;
    } else {
        int result = cEncrypt(msg);
        //PyBuffer_Release(&msg); // ALWAYS have to release buffer memory or you will get a segmentation fault!
        return Py_BuildValue("i", result);
    }
}

static PyMethodDef pySpeckMethods[] = {
    {"encrypt", encrypt, METH_VARARGS, "Encrypts bytestring"},
    {NULL, NULL, 0, NULL} // Sentinel 
};

static struct PyModuleDef pySpeck = {
    PyModuleDef_HEAD_INIT,
    "pySpeck",
    "Python Speck",
    -1,
    pySpeckMethods
};

PyMODINIT_FUNC PyInit_pySpeck(void) {
    return PyModule_Create(&pySpeck);
}

