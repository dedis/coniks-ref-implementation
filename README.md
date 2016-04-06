# CONIKS/CoSi: CoSiNIKS

This is a fork of the CONIKS reference implementation. Please check the 
[original repository](https://github.com/citp/coniks-ref-implementation) 
on how-to set-up and use the CONIKS test-server and test-client.

## Changes in this fork

The signed tree roots (STRs) get signed by a collective (CoSi) signature 
instead of by the identity provider only.
The main changes can be found [here](XXX).

In order to run this PoC CoSi integration make sure you understood 
how-to run and use the original reference implementation first. 
Then, you need a current [CoSi release]
(https://github.com/dedis/cothority/releases/tag/0.7.5). Copy all the
the files you extracted from the release archive to the class path 
(which you can specify in the `CLASS_DEST` variable in the [MAKEFILE]
 (https://github.com/dedis/coniks-ref-implementation/blob/master/coniks_server/Makefile). 
 Also copy `dedis-servers.toml` to the same path and rename the file to
 `servers.toml`.
 
 While running the test-server you should see an output similar to:
 ```
 Written data to sign to file /var/folders/z7/qx3bqsrx79755g3tzql2s8200051m1/T/data-to-sign223591340184638199.bin
 Output of running [cosi, sign, file] is:
 3 : ( main.signFile: 150) - &{[190 114 198 72 77 18 57 191 211 91 83 125 162 205 123 191 56 53 59 102 195 38 8 211 140 195 180 97 134 254 86 61] 0e73cf5cf066ce7c4a96d5ca3a8540628d6f81a3e6753b2c0b68e698a1070269 0c387a8617ce566d4c3ddd99c9f3cd583aa96228cfb5963d2ae0580c9594bd5e}
 3 : ( main.signFile: 155) - Signature written to: /var/folders/z7/qx3bqsrx79755g3tzql2s8200051m1/T/data-to-sign223591340184638199.bin.sig
 
 CoSi signature:
 {
 	"Sum": "vnLGSE0SOb/TW1N9os17vzg1O2bDJgjTjMO0YYb+Vj0=",
 	"Challenge": "DnPPXPBmznxKltXKOoVAYo1vgaPmdTssC2jmmKEHAmk=",
 	"Response": "DDh6hhfOVm1MPd2ZyfPNWDqpYijPtZY9KuBYDJWUvV4="
 }
``` 


