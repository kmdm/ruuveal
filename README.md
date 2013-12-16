ruuveal
=======

ruuveal decrypts encrypted zip files contained in RUUs released by HTC.

ruuveal has been (somewhat) tested but that doesn't mean it won't cause the end of the world as we know it. You have been warned. 

You will need to extract the zip file from the RUU executable before you can use this tool - use Google, there are a few methods.

One such method is unruu, available from:-

 * https://github.com/kmdm/unruu

Supported Devices
-----------------

The following devices are currently supported by ruuveal:-

* HTC One SC (cp2dcg)
* HTC One ST (cp2dtg)
* HTC One SU (cp2dug)
* HTC Desire 600 - China Unicom (cp3dug)
* HTC J Butterfly (deluxe\_j)
* HTC J DNA (deluxe\_u)
* HTC Butterfly (deluxe\_ub1)
* HTC Butterfly S (dlxp\_u)
* HTC Butterfly S LTE (dlxp\_ul)
* HTC One XT (endeavor\_td)
* HTC One X (T3) (endeavor\_u)
* HTC One X+ (enrc2\_u)
* HTC One X+ (enrc2b\_u)
* HTC One X (S4) (evita)
* HTC One X+ LTE (evitare\_ul)
* HTC Incredible 4G LTE (fireball)
* HTC One XC (jel\_dd)
* HTC Evo 4G LTE (jewel)
* HTC One SV (k2\_plc\_cl)
* HTC One SV (k2\_u)
* HTC One SV (k2\_ul)
* HTC One Mini U (m4\_u)
* HTC One Mini UL (m4\_ul)
* HTC One U (m7\_u)
* HTC One UL (m7\_ul)
* HTC One WLJ (m7\_wlj)
* HTC One WLS (m7\_wls)
* HTC One WLV (m7\_wlv)
* HTC One - China Mobile (m7cdtu)
* HTC One - China Unicom (m7cdug)
* HTC One - China Telecom (m7cdwg)
* HTC Desire SV (magnids)
* HTC Droid DNA (monarudo)
* HTC First (mystul)
* HTC Desire X (proto)
* HTC Desire V (protodug)
* HTC T329t (prototd)
* HTC One Max - China Telecom (t6dwg)
* HTC One Max WHL (t6whl)
* HTC One VX (tc2)
* HTC One S (ville)
* HTC One S C2 (villec2)


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

Usage
-----

    $ ruuveal [options] --device DEVICE source.zip output.zip

For example:

    $ ruuveal --device jewel rom_01.zip rom_01_decrypted.zip

Once you have decrypted the zip file, it should unzip with any standard zip utility.

Bugs/Issues
-----------

Please report any bugs/issues you find - Thanks!

Credits
-------

* joeykrim - Making me aware HTC has released an encrypted RUU.
* RaYmAn   - Being a sounding board / working through some weird logic.
* HTC      - For continuing to release great devices.
