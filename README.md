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
is often used as an example to illustrate the shortcomings of Internet of Things
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

The design for the module is fairly simple, as seen in the Python object oriented
interface for the library found in `test/pySpeckTest.py` in the repository.
```python
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
contained in the ciphertext. 

Now that we have discussed the overarching design for the project, let us turn our
attention to the implementation details. The majority of the work for this project
was learning how to utilize the C/Python API to pass Python objects to C/C++ code,
translate the Python data into a standard C/C++ data type, and reversing the 
process to return a result to the Python caller. Once a method for this was 
finalized, the process for encrypting and decrypting data was nearly identical 
for the two ciphers, so to reduce redundancy I will only step through the code for
the Speck cipher. The following function is responsible for acting as the middle
man between Python and C++ for the encryption function.
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
create a random initialization vector and read a string translation into the 
`iv_string` variable. A CBC mode encryption object is then created using the
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
and `iv_string` is translated back into its original `byte` form. A CBC mode 
decryption object is created and given the key and initialization vector, and,
just as before, the ciphertext is sent through a transformation filter that applies
the decryption operation to it. The resulting plaintext is saved to the `plain_text`
variable and returned to the caller. 

## Performance

To benchmark the performance of CryptoLight, I saved the text of random Wikipedia
pages to a text file until it reached a size of about 200 kB. This text was then
broken into chunks and fed through the encryption function and saved to another 
text file. This text file was similarly sent through the decryption function and 
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

## Retrospective

While I set out to learn more about the Simon and Speck family of ciphers, I did
not end up learning very much about them outside of the papers written on them.
Much of the implementation time, which was much longer than I anticipated, was 
spent fighting and ardous war of attrition with the C/Python API as it threw
segmentation faults for nearly every line of code I wrote. I did, however, learn
alot about how Python really works under the hood, and I would recommend this 
project readily to people who are interested in learning more about how 
interpreters work. If you were like me and want to learn more about cryptography,
though, stick with plain C++ (or Rust, to avoid the segmentation faults entirely).

## References 
1. Beaulieu R, Shors D, Smith J, Clark ST, Weeks B, Wingers L (2017) Notes on the design and analysis of SIMON and SPECK. IACR Cryptology ePrint Archive 560
2. "Crypto++ Library 8.2 | Free C++ Class Library of Cryptographic Schemes", Cryptopp.com, 2019. [Online]. Available: https://www.cryptopp.com/. [Accessed: 04- May- 2019].
3. Python/C API Reference Manual — Python 3.7.3 documentation", Docs.python.org, 2019. [Online]. Available: https://docs.python.org/3/c-api/. [Accessed: 04- May- 2019].