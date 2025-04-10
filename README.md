# km-iprestricted-ca

This is mostly a CA subsystem with external signers. There
are 2 external signers in this package that provide the
crypto.Signer interface.

The cmd diretctory contains the command line utility for
a ca-signer that generetaes ip restricted role-requesting certificates
for keymaster.

A CA should be provided and this CA should be added to the list
of adminCA for keymsterd.

The lib directory contains libraries for crypto.Signers two
are curretnnly implemented kmssigner and yubikey signers (piv)


* lib/kmssigner. AWS KMS.
* lib/yksigner. Yubikeys using PIV interface



## signer libraries

### lib/kmssigner

uses AWS KMS service for signatures. The code
supports both RSA and ECDSA signatures.

### lib/yksigner

Uses a yubikey in PIV mode to as a signer. The library
allows users to use explicit public keys and supports:
ECDSA (P256 and P384) and ED25519 (in yubikeys with firmware>= 5.7).


#### generating the key

There is no user facing code to generate the keys. The recomended way is to
use `ykman` to let the tubikey generate its keys

generate an Ed25519Key:
> ykman piv keys generate -a ED25519 9a -

Generate an P384 key:
> ykman piv keys generate -a ECCP384 9a -




