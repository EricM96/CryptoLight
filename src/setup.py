from distutils.core import setup, Extension

CryptoLightFunctions = Extension("CryptoLightFunctions", sources=["cryptolight.cpp"],
                                       #include_dirs=["/usr/local/include"],
                                       libraries=["cryptopp"],
                                       #runtime_library_dirs=["/usr/local/lib"]
                                       )

setup(name="CryptoLightFunctions",
      version="0.1",
      description="Performant speck code for Python IoT systems.",
      ext_modules=[CryptoLightFunctions])
