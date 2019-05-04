echo ----BUILDING EXTENSION----
python3 setup.py build
echo ----EXTENSION BUILT COPYING FILES----
cp build/lib.linux-x86_64-3.6/CryptoLightFunctions.cpython-36m-x86_64-linux-gnu.so ../test/
echo ----REMOVING BUILD FILES----
rm -r build/
echo --------------------
echo --------------------
echo --------------------
echo ----RUNNING TEST----
python3 ../test/pySpeckTest.py Simon
