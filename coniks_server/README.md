#CONIKS Server

Copyright (C) 2015-16 Princeton University.

https://coniks.cs.princeton.edu

##Introduction
This is a basic implementation of a server for the CONIKS key management service. It currently supports new key registrations, key lookups, and can generate consistency proofs and signed directory snapshots. It is designed to communicate with the [CONIKS test client](https://github.com/citp/coniks-ref-implementation/tree/master/coniks_test_client).

##Using the Server

###Preparing SSL
CONIKS servers communicate via SSL/TLS connections with any client or other key servers.
Unless you already have a valid certificate for your server, you will need to create self-signed certificates:
```
keytool -genkeypair -alias <alias> -keyalg RSA -validity 365 -keystore <keystore>
keytool -export -alias <alias> -keystore <keystore> -rfc -file <alias>.cer
keytool -import -alias <alias> -file <alias>.cer -keystore <truststore>
```
You will be asked to enter a password for each the keystore and the truststore. Make sure you remember these passwords. Notice that the self-signed certificates are set to expire within 365 days here.

###Server Configuration
- *ServerConfig.java*: You will need to fill in the following fields in the ```ServerConfig()``` constructor. If you would like, you may also create a config file that contains the information from the following fields in this exact order.
```
<port number>
<alias> (same alias used for your certificates)
<full server hostname>
<path to logs>/msg-handler-%g
<path to logs>/epoch-timer-%g
<path to logs>/server-%g
<epoch length in milliseconds>
<path to keystore>/<keystore>
<keystore password>
<path to truststore>/<truststore>
<truststore password>
```
If you're using a config file, make sure it is only readable by the users intended to use the CONIKS server.
- *ConiksServer.java*: Set the number of dummy users in the tree at startup time in the **SIZE** field.
Set the path to the configuration file in the **CONFIG_FILE** field if used, and use the appropriate ```ServerConfig``` constructor.
- *ServerOps.java*: Set the path to the debugging log in the **debugLog** field.
- *coniks_server.sh*: Set the **LOG_PATH** to be the the same <path to logs> used in the server configuration.

###Building
We understand that people may not necessarily want to build and run the server on the same machine. 
- Prerequisites:
You'll need Java 7 or greater and need to ensure that the protobufs have been compiled with the most recent version of protoc.
- Compiling:
Specify where you would like the .class files to be placed, and run make:
```
export CLASS_DEST=/path/to/classes
make 
```
- Pushing the compiled code to a remote machine:
In the *Makefile*, set the **PUBUSER**, **PUBHOST**, and **PUBPATH** variables to the appropriate values. Then run:
```
make pubbin
```
This step assumes the **PUBUSER** has ssh access to the remote machine.
- Pushing the run script to a remote machine:
```
make pubscr
```
This step also assumes the **PUBUSER** has ssh access to the remote machine **PUBHOST**, and may require you to change the permissions of the script on the remote host.

###Running
We provide a run script for the CONIKS server *coniks_server.sh*, which allows you to run the server as a background process, as well as clean up any logs written by the server.

The run script supports three commands: 
- ```start```: start the CONIKS server in the background, if it isn't running already.
- ```stop```: stop the CONIKS server.
- ```clean```: remove all logs written by the server, and stop the server if it's running.
For example, to start the server, use
```./coniks_server.sh start```
Analogously to stop the server, and remove the logs.

## Disclaimer
Please keep in mind that this CONIKS reference implementation is under active development. The repository may contain experimental features that aren't fully tested. We recommend using a [tagged release](https://github.com/citp/coniks-ref-implementation/releases).

##Documentation
[Read the server's Java API (javadoc)](https://citp.github.io/coniks-ref-implementation/org/coniks/coniks_server/package-summary.html)
