ruuveal ALPHA
=============

ruuveal decrypts encrypted zip files contained in RUUs released by HTC.

It is currently an ALPHA version, meaning it probably has bugs or will cause the end of the world as we know it. You have been warned. 

You will need to extract the zip file from the RUU executable before you can use this tool - use Google, there are a few methods.

One such method is unruu, available from:-

 * https://github.com/kmdm/unruu

Supported Devices
-----------------

The following devices are currently supported by ruuveal:-

 * endeavor\_u - HTC One X (T3)
 * evita - HTC One X (S4)
 * fireball - HTC Incredible 4G
 * jewel - HTC EVO 4G LTE
 * ville - HTC One S

If your device is not supported and you would like it supported please open an issue in the tracker with the device name, codename and a link to the most recent hboot file for the device. (Not a link to the full RUU!)

Compilation
-----------

ruuveal requires the development files for mcrypt. On Debian/Ubuntu based systems you can probably get these by installing the libmcrypt-dev package. On Redhat based systems the package to install is probably libmcrypt-devel. 

Once you have these files you can compile the development tree as follows:-

    $ ./autogen.sh
    $ ./configure
    $ make

Please note that once release tarballs area made the autogen.sh step will not be required since release tarballs ship with the configure script and the Makefile already generated.

Downloads
---------

Downloads are currently available from:-

* http://psi.kennynet.co.uk/ruuveal/

Please note that only snapshots are available at present but these will allow you to skip the autogen.sh step above and just run configure and make. 

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
* RaYmAn   - Being a sounding board / working through some weird logic.
* HTC      - For continuing to release great devices.
