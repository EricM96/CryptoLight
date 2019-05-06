from distutils.core import setup, Extension

CryptoLightFunctions = Extension("CryptoLightFunctions", 
                                       sources=["cryptolight.cpp"],
                                       libraries=["cryptopp"],
                                       )

setup(name="CryptoLightFunctions",
      version="0.1",
      description="Performant simon and speck code for Python IoT systems.",
      ext_modules=[CryptoLightFunctions])
