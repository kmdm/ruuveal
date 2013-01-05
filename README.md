ruuveal ALPHA
=============

ruuveal decrypts the encrypted zip files contained in RUUs released by HTC.

It is currently an ALPHA version, meaning it probably has bugs or will cause the end of the world as we know it. You have been warned. 

You will need to extract the zip file from the RUU executable before you can use this tool - use Google, there are a few methods.
Example: http://mobility.forumsee.com/a/m/s/p12-9522-076282--extract-the-rom-from-htc-ruu.html

Usage
-----

    $ ruuveal device encrypted-rom.zip output.zip

For example:

    $ ruuveal jewel rom_01.zip rom_01_decrypted.zip

Once you have decrypted the zip file, it should unzip with any standard zip utility.

Bugs/Issues
-----------

Please report any bugs/issues you find - Thanks!

Credits
-------

* joeykrim - Making me aware HTC has released an encrypted RUU.
* RaYmAn   - Being a sounding board / working through some unusual logic.
* HTC      - For continuing to release great devices.
 
Compile
-------

sudo apt-get install libmcrypt-dev (if not done previously sh autogen.sh will throw "`AM_PATH_LIBMCRYPT' not found")
sh autogen.sh
./configure ; make
