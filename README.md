This is my student work, done so far from 2008 till now (2012), may be some
would find it usefull.

Licensed under BSD License.

No warranty, no bugfixing, some things not working or buggy :-)
Use at your own risk :-)

This is applications for UEFI framework/BIOS:

* Boot menu and bootmanager editor
* User/admin user management
* Trusted/mesured boot using openssl and gost algo
* CRC check for UEFI modules
* Ldap integration
* PKI/X.509/CDP/CRL intergations for two-factor auth
* pkcs11 and tokens (rutoken and etoken) support for user auth
* multiboot spec support. Can load linux kernel directly w/o grub

Used UEFI framework TianoCore (tianocore.org). Tested only on x32/x64 Intel
based arch.

To use this pkgs clone edk2 tree, put ApplicationPkg into cloned tiano tree 
as a submodule, then include dedicated pkg inf files into build.

Compiled only under MS Windows, using VC compiler and WINDDK. Compilation
under Linux not tested.

You can use OVMF package to run under qemu.

Massively used to derive some code and use as libraries:
* OpenSSL 1.0.1 + engine_gost (crypto functions, gost functions, etc.)
* OpenLDAP (client only)
* OpenCT (for ccid)
* OpenSC (for rutoken and etoken code)
* Microsoft cryptoki (for some pkcs11 defines and code)
* examples and code from tianocore source tree (bds, setupbrowser, etc.)

Everything as one single commit (sorry for that).

Enjoy.
