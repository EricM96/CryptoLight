echo ----BUILDING EXTENSION----
python3 setup.py build
echo ----EXTENSION BUILT COPYING FILES----
cp build/lib.macosx-10.14-x86_64-3.7/CryptoLight.cpython-37m-darwin.so ../test/
echo ----REMOVING BUILD FILES----
rm -r build/
echo --------------------
echo --------------------
echo --------------------
echo ----RUNNING TEST----
python3 ../test/pySpeckTest.py
