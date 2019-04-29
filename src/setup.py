from distutils.core import setup, Extension

pySpeck = Extension("pySpeck", sources=["cSpeck.cpp"])

setup(name="pySpeck",
      version="0.1",
      description="Performant speck code for Python IoT systems.",
      ext_modules=[pySpeck])