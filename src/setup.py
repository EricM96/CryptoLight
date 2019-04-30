from distutils.core import setup, Extension

CryptoLight = Extension("CryptoLight", sources=["scratch.cpp"],
                                       include_dirs=["/usr/local/include"],
                                       libraries=["cryptopp"],
                                       runtime_library_dirs=["/usr/local/lib"])

setup(name="CryptoLight",
      version="0.1",
      description="Performant speck code for Python IoT systems.",
      ext_modules=[CryptoLight])
