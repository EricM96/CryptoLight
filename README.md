# CryptoLight
A lightweight cryptography module for Python.

* Eric McCullough 
* CSC 690 Final Project
* Spring 2019

## Motivation

With the advent of the Internet of Things, many time and safety critical devices
are being networked together in the same manner computers are connected to the
Internet. While this has many promising applications in creating smart, reactive
environments and technologies (for example, smart homes, self driving cars, and
smart medical technology), there has been concern among experts that these systems
are highly insecure. These devices are often much smaller than a traditional
computer and do not have access to the computational resources necessary to
implement the security mechanisms common to the Internet. Medical technology
is often used as an example to illustrate the deficiencies of Internet of Things
security. While having embedded medical technology, such as pacemakers, connected
to the Internet is highly desirable to health care professionals in order to
give them access to real-time, potentially life-saving data, you do not want
hackers to gain access to sensitive personal data, or worse, carry out a malicious
attack against a patient.

To combat this weakness, a team of cryptographers working for the NSA proposed
the Simon and Speck families of lightweight block ciphers in 2011. The goal of
these ciphers is to provide a reasonable level of security to computationally
constrained systems. While they are both highly performant in constrained
environments, Speck ciphers are optimized towards hardware constrained devices
while Simon ciphers favor software constrained environments. This was accomplished
by designing Simon ciphers around bitwise AND operations and Speck ciphers around
modular addition.

For my final project, I wanted to gain a better familiarity with these ciphers
by implementing an extension to the Python interpreter that would make these
cryptographic functions available to Internet of Things systems implemented in
Python. While Simon and Speck are both families of ten cryptosystems, each with
varying block and key sizes, I decided to utilize the CryptoPP library in C++
to gain access to its pre-implemented schemes for Simon and Speck using 128 bit
keys and blocks.

## Design and Implementation 

The following sections will describe each feature of the system and its implementation.
To ensure thoroughness, I will provide snippets of critical source code and provide an 
explanation for its functionality and design. 

When creating a new extension for the Python interpreter, you implement C/C++ code to 
carry out the operations you want the library to have and utilize the C/Python API to act 
as a middleman between Python and your C++ code. Put simply, the C/Python API acts 
as a translator, taking Python data objects and turning them into C data types and vice versa. 

While the C/Python API provides an interface for passing data from Python to C/C++ functions,
there does not exist an intuitive way of exporting a C++ class as a module. To preserve 
object oriented design principles, I implemented the functions for CryptoLight and provided
a Python object oriented interface to organize those functions into a class. This breaks the
project into four distinct categories of code: the object oriented interface, the C/Python
API translation functions, the C++ cryptography functions, and the C/Python API code for
exporting the C++ code as a Python library. The following sections will cover these in 
sequence. 

### Object Oriented Interface
The design for the module is fairly simple, as seen in the Python object oriented
interface for the library found in `test/pySpeckTest.py` in the repository. 
```python
import CryptoLightFunctions

class CryptoLight(object):
    def __init__(self, mode):
        CryptoLightFunctions.generateKey()
        if mode == "Simon":
            self.encrypt_function = CryptoLightFunctions.simonEncrypt
            self.decrypt_function = CryptoLightFunctions.simonDecrypt
        elif mode == "Speck":
            self.encrypt_function = CryptoLightFunctions.speckEncrypt
            self.decrypt_function = CryptoLightFunctions.speckDecrypt

    def encrypt(self, plaintext):
        ciphertext = self.encrypt_function(plaintext)
        while b'\x00' in ciphertext:
            ciphertext = self.encrypt_function(plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        return self.decrypt_function(ciphertext)
```
When utilizing the library, create an instance of the CryptoLight class and 
pass in a string containing either `"Simon"` or `"Speck"` as the argument. The 
class will then set the encryption and decryption functions appropriately, 
according to which cipher you chose. A key is also randomly generated within the 
C++ module and written to a file within the object's directory which can be 
retrieved by the module at the time of encryption or decryption. 

I did encounter some difficulty with passing data between Python and the C++ 
module when it came to the encryption function. The ciphers could inadvertently
encrypt characters to null bytes. While it was possible to translate these null
byte embedded strings into Python bytestrings, this process could not be reversed 
as both C and C++ strings interpret a null byte as the end of the string. This led
to all characters following the null byte to be lost and the decryption function
failing, as the resulting input was not the proper length for the block cipher. 
After several hours spent trying to alleviate this problem, the encryption function
was set into a while loop that would continue encrypting plaintext until the 
resulting ciphertext was free of null bytes. While this certainly does not have
a favorable effect on the performance of the cipher, it had to be done to meet 
the deadline for the project. To prevent this from entirely tanking the performance
of the module, it is preferable to break large amounts of data into chunks before
passing it the the encrypt function to lower the probability of a null byte being
contained in the ciphertext. The decryption method is much more straight forward, as
it simply needs to call the selected decryption function and return the result.

### C/Python API Translation Functions 

The majority of the work for this project
was learning how to utilize the C/Python API to pass Python objects to C/C++ code,
translate the Python data into a standard C/C++ data type, and reversing the 
process to return a result to the Python caller. Similar to how parallel computing
projects are notoriously difficult to debug, the C/Python API offers no assistance 
to the programmer in regard to identifying problems in their code. I also found the
documentation for the API's extensive library to be rather unhelpful in that many of 
the functions have similar names and descriptions, when in reality they each serve a 
highly specific purpose that I had to discover through brute trial and error. Failure
to utilize a function for its single specific purpose leads to a generic 
segmentation fault, and does not provide information on what line, file, or function 
caused the error.  

Once this method was finalized however, it was essentially identical for both the 
Simon and Speck code, so to reduce redundancy, I will just go over the code pertaining
to Speck. The following function, found in `src/cryptolight.cpp` is responsible for acting 
as the middle man between Python and C++ for the encryption function.
```C++
static PyObject *speckEncrypt(PyObject *self, PyObject *args) {
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
```
speckEncrypt returns a pointer to a Python object and takes in one or more 
pointers to Python objects as an argument. `PyArg_ParseTuple(args, "y", &msg)`
takes the arguments from Python and parses it to the C string variable `msg`. 
`"y"` indicates that the Python argument should be a bytestring. Should this call
fail, NULL is returned to the Python caller, indicating that an incorrect data
type was passed. Following this, `msg` is passed to the encryption function, and 
a C++ string containing the initialization vector and cipher text is returned. 
The result is then parsed into Python Bytes using `PyBytes_FromStringAndSize` and
returned to the Python caller. Inversely, the following function handles the 
decryption method.
```C++
static PyObject *speckDecrypt(PyObject *self, PyObject *args) {
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
```
This function starts off much in the same way as the proceeding function. The 
differences start when parsing the arguments from Python. The `"S"` option 
indicates that the argument is to be `PyBytes` and these are parsed into a pointer
to a Python object. This is because a the `"y"` sometimes fails when handling 
encrypted bytes. `PyBytes_AsString` provides a method for taking the PyBytes
and parses it into a null terminated C++ string. This string is passed to the C++
decryption function and the resulting string is translated back into `PyBytes`
and returned to the caller.

### Encryption and Decryption Functions

Now that we have discussed how values are passed to and from Python, let's turn
our attention to the actual encryption and decryption functions. These were 
implemented using CryptoPP's extensive library of cryptography modules. Again,
the Simon and Speck code are nearly identical, so I will only go over Speck. In
order to make the Speck code work for Simon, one only needs to change all the calls
to features of `SPECK128` to `SIMON128`. The following function handles encryption
for Speck. 
``` C++
std::string cSpeckEncrypt(char *plain_text) {
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
```
The first line declares string variables that will contain the ciphertext and
initialization vector respectively. Then, they key is extracted from its file and
translated into CryptoPP's `SecByteBlock` format. The next three lines of code
creates a random initialization vector using a global CryptoPP random number generator 
 and reads a string translation into the 
`iv_string` variable. A `CBC_Mode` encryption object is then created using the
`SPECK128` scheme and outfitted with the key and initialization vector. The 
`plain_text` variable is then pumped through a transformation filter that applies
the encryption function and saves the resulting ciphertext to the `cipher_text` 
variable. Because the initialization vector will be needed to decrypt the 
ciphertext, it must be returned as well. To accomplish this, the `iv_string` and
`cipher_text` string are concatenated together, and the resulting aggregate string
is returned to the caller. Next, let's look at the inverse decryption function.
```C++
std::string cSpeckDecrypt(std::string aggregate_str) {
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
```
First variables are made to hold the resulting plaintext and initialization vector.
Then, the aggregate string from the encryption function is split between the 
initialization vector and plaintext. The key is once again extracted from its file,
and `iv_string` is translated back into its original `byte` form. A `CBC_Mode` 
decryption object is created and given the key and initialization vector, and,
just as before, the ciphertext is sent through a transformation filter that applies
the decryption operation to it. The resulting plaintext is saved to the `plain_text`
variable and returned to the caller. 

### Creating the Module 

The process by which the C++ code into a Python module is fairly boiler plate, and simply
requires providing the proper configuration variables and files. In the C++ code, you must
organize your functions into a `PyMethodDef` array. The method array for CryptoLight is shown 
below
```C++
static PyMethodDef CryptoLightMethods[] = {
    {"generateKey", generateKey, METH_NOARGS, "Generates key for encryption and stores it in a file"},
    {"speckEncrypt", speckEncrypt, METH_VARARGS, "Encrypts bytestring"},
    {"speckDecrypt", speckDecrypt, METH_VARARGS, "Decrypts bytestring"},
    {"simonEncrypt", simonEncrypt, METH_VARARGS, "Encrypts bytestring"},
    {"simonDecrypt", simonDecrypt, METH_VARARGS, "Decrypts bytestring"},
    {NULL, NULL, 0, NULL} // Sentinel 
};
```
Each item in the array corresponds to a function that will exist in the Python module. The first
entry in each item is the name of the function that will be callable from Python. The second is the
C++ function that it corresponds to (I used the same name for both). Note that only the translation
functions are exported, as calls to the C++ encryption and decryption functions are embedded in the
translation functions. The third item in each entry uses a macro from the C/Python API to indicate
what type of arguments the functions expect. This is almost always `METH_VARARGS` except for the case
of the `generateKey` function, which does not expect arguments. The last item in each entry provides
a short description of what that function does. The last entry, containing NULL values, is a sentinel
value which indicates the end of the `PyMethodDef`. 

After the `PyMethodDef` struct is created, it is used to create a `PyModuleDef` struct, which
provides more information about the module as a whole. Here's the `PyModuleDef` for CryptoLight
```C++
static struct PyModuleDef cryptoLight = {
    PyModuleDef_HEAD_INIT,
    "CryptoLight",
    "CryptoLight",
    -1,
    CryptoLightMethods 
};
```
This provides the name, a description of, the number of methods (-1 makes it dynamically sized to
the size of the `PyMethodDef`), and the `PyMethodDef` array. After this struct is made, all that
is left is passing it to a generic `PyMODINIT_FUNC` function that creates the module object.
```C++
PyMODINIT_FUNC PyInit_CryptoLightFunctions(void) {
    return PyModule_Create(&cryptoLight);
}
```
This invokes built in functions in the C/Python API to take the struct and create a library
object from it; however, in lue of a MAKE file, you must provide a Python `setup.py` script
to provide information on how to compile and build the library.
```Python
from distutils.core import setup, Extension

CryptoLightFunctions = Extension("CryptoLightFunctions", 
                                       sources=["cryptolight.cpp"],
                                       libraries=["cryptopp"],
                                       )

setup(name="CryptoLightFunctions",
      version="0.1",
      description="Performant simon and speck code for Python IoT systems.",
      ext_modules=[CryptoLightFunctions])
```
First, an Extension object is created and given the name of the `PyMethodDef` in
the C++ source, a list containing all of the C++ source files for the new module,
and any libraries the source files depend on. Then the `setup` function is called
and provided the name it should give the extension object, the version number,
a description, and a list of the `Extension` objects to be included in the 
library. 

## Performance

To benchmark the performance of CryptoLight, I saved the text of random Wikipedia
pages to a text file until it reached a size of about 200 kB. This text was then
broken into chunks and fed through the encryption function and saved to another 
text file. This enciphered text file was similarly sent through the decryption function and 
saved to another text file to assure that the operations executed successfully. 
This process was repeated for CryptoLight's Simon and Speck implementations as 
well as Pycryptodome's AES implementation to see how they performed against a more
traditional block cipher. It is worth noting that this experiment was run on my desktop 
computer, not a constrained environment like they were intended for. Nevertheless,
given my limited resources, it should serve as a sufficient benchmark for my system.
The following table describes the results.

| Cipher  | Time on benchmark task (seconds)
|---------|:-----------------------
| Simon   | 0.09959697723388672
| Speck   | 0.09698772430419922
| AES     | 0.1481614112854004

As expected, Simon and Speck both outstripped AES in terms of speed, but the degree
to which it does is not reflective of the vast difference in computational
complexity between the lightweight ciphers and AES. This could be due to the size of 
the test data file not being enough to allow the lightweight ciphers to show their 
performance benefits, but it seems more likely that my implementations are simply
inefficient. Pycryptodome is implemented and maintained by a full team of expert developers, 
who are likely far more knowledgeable than I am when it comes to writing cryptography
software. Regardless, this experiment does demonstrate that Simon and Speck can outsrip
AES in speed of encryption. The simplicity of Simon and Speck could indeed make or break
the ability of constrained devices to cary out enciphering and deciphering in time
and safety critical functions. 

## Retrospective

While I set out to learn more about the Simon and Speck family of ciphers, I did
not end up learning very much about them outside of their papers.
Much of the implementation time, which was much longer than I anticipated, was 
spent fighting an ardous war of attrition with the C/Python API as it threw
segmentation faults for nearly every line of code I wrote. I did, however, learn
a lot about how Python really works under the hood, and I would recommend this 
project readily to people who are interested in learning more about how 
interpreters work. If you were like me and want to learn more about cryptography
though, stick with plain C++ (or Rust, to avoid the segmentation faults entirely).

## References 
1. Beaulieu R, Shors D, Smith J, Clark ST, Weeks B, Wingers L (2017) Notes on the design and analysis of SIMON and SPECK. IACR Cryptology ePrint Archive 560
2. "Crypto++ Library 8.2 | Free C++ Class Library of Cryptographic Schemes", Cryptopp.com, 2019. [Online]. Available: https://www.cryptopp.com/. [Accessed: 04- May- 2019].
3. Python/C API Reference Manual — Python 3.7.3 documentation", Docs.python.org, 2019. [Online]. Available: https://docs.python.org/3/c-api/. [Accessed: 04- May- 2019].