/*
  Copyright (c) 2015, Princeton University.
  All rights reserved.
  
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are 
  met:
  * Redistributions of source code must retain the above copyright 
  notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above 
  copyright notice, this list of conditions and the following disclaimer 
  in the documentation and/or other materials provided with the 
  distribution.
  * Neither the name of Princeton University nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
  POSSIBILITY OF SUCH DAMAGE.
 */

package org.coniks.coniks_server;

import org.coniks.coniks_common.C2SProtos.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;
import java.security.interfaces.*;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * Implements all operations involving digital signatures
 * that a CONIKS server must perform.
 * Current encryption/signing algorithm used: RSA with SHA-256.
 *
 * @author Marcela S. Melara (melara@cs.princeton.edu)
 * @author Michael Rochlin
 */
public class SignatureOps {

    private static ServerConfig CONFIG = null;

    // TODO use a config file instead
    // A PoC way to call CoSi
    // Currently specifying the servers doesn't work.
    // See: https://github.com/dedis/cothority/issues/344
    private static String CWD = System.getProperty("user.dir") + "/bin";
    private static String[] COSI_SIGN_CMD = {"cosi", "sign", "file"};
    private static boolean COSI_ENABLED = true;

    /**
     * Initialize the signature operations with the
     * server configuration {@code config}.
     */
    public static void initSignatureOps(ServerConfig config) {
        CONFIG = config;
    }

    /**
     * Digitally sign the {@code input}.
     *
     * @return The {@code byte[]} containing the digital signature
     * of the {@code input}.
     * @throws A RuntimeException if there is a problem with the private key
     *           loaded from the server's keystore.
     */
    public static byte[] sign(byte[] input) {


        RSAPrivateKey MY_PRIV_KEY = KeyOps.loadSigningKey(CONFIG);

        byte[] signed = null;

        if (MY_PRIV_KEY == null) {
            throw new RuntimeException("borked pk?");
        }

        try {
            if (COSI_ENABLED) {
                return cosiSign(input);
            }else {
                Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(MY_PRIV_KEY, new SecureRandom());
                signer.update(input);

                signed = signer.sign();
                return signed;
            }

        } catch (NoSuchAlgorithmException e) {
            TimerLogger.error("RSA is invalid for some reason.");
        } catch (InvalidKeyException e) {
            TimerLogger.error("The given key is invalid.");
        } catch (SignatureException e) {
            TimerLogger.error("The format of the sig input is invalid.");
        } catch (IOException e) {
            e.printStackTrace();
        }
        return signed;
    }

    public static byte[] cosiSign(byte[] input) throws IOException {
        byte[] signedOrNull = null;
        String tmpBlob = "";
        try {
            // write input data to a temporary file:
            File temp = File.createTempFile("data-to-sign", ".bin");
            tmpBlob = temp.getAbsolutePath();
            FileOutputStream fos = new FileOutputStream(temp);
            fos.write(input);
            System.out.println("Written data to sign to file " + tmpBlob);
            fos.close();
            // assume we used `make` with variable
            // `CLASS_DEST` set to the same value as the one specified in CWD
            // and run `sh coniks_server.sh start` to run the CONIKS ref implementation
            File cwd = new File(CWD);
            String[] cmd = Arrays.copyOf(COSI_SIGN_CMD, COSI_SIGN_CMD.length +1);
            cmd[COSI_SIGN_CMD.length] = tmpBlob;
            Process process = new ProcessBuilder(cmd).directory(cwd).start();
            InputStream is = process.getInputStream();

            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            String line;

            System.out.printf("Output of running %s is:\n", Arrays.toString(COSI_SIGN_CMD));
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
            // TODO signature is JSON/base64 encoded, extract challenge&response
            // and binary encode them instead ...
            signedOrNull = Files.readAllBytes(Paths.get(tmpBlob+".sig"));
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // "defer" cleanup of temp files
            if (!tmpBlob.isEmpty()) {
                File d = new File(tmpBlob);
                Files.deleteIfExists(d.toPath());

                File s = new File(tmpBlob+".sig");
                // print the signature before deleting the file
                System.out.println("CoSi signature:");
                List<String> sl = Files.readAllLines(s.toPath());
                for (String l : sl) {
                        System.out.println(l);
                }

                Files.deleteIfExists(s.toPath());
            }
        }
        return signedOrNull;
    }

    /**
     * Verify a given server {@code keyOwner}'s digital signature {@code signature}
     * on the message {@code msg}.
     *
     * @return {@code true} if the signature on the message is valid, {@code false}
     * otherwise.
     */
    public static boolean verifySig(byte[] msg, byte[] signature, String keyOwner) {

        RSAPublicKey pubKey = KeyOps.loadPublicKey(CONFIG, keyOwner);

        try {

            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(pubKey);
            verifier.update(msg);

            return verifier.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            TimerLogger.error("SHA256withRSA is invalid for some reason.");
        } catch (InvalidKeyException e) {
            TimerLogger.error("The given key is invalid.");
        } catch (SignatureException e) {
            TimerLogger.error("The format of the input is invalid: " + e.getMessage());
        }

        return false;
    }

    /**
     * Makes a DSAPublicKey from the params
     */
    public static DSAPublicKey makeDSAPublicKeyFromParams(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DSA");
            KeySpec publicKeySpec = new DSAPublicKeySpec(y, p, q, g);
            return (DSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidParameterException e) {
            TimerLogger.error("The given DSA key is invalid.");
        } catch (InvalidKeySpecException e) {
            TimerLogger.error("The given key params are invalid.");
        } catch (NoSuchAlgorithmException e) {
            TimerLogger.error("DSA is invalid for some reason.");
        }
        return null;
    }

    // makes a DSA key from the DSAPublicKeyProto protobuf
    public static DSAPublicKey makeDSAPublicKeyFromParams(DSAPublicKeyProto pkProto) {
        BigInteger p = new BigInteger(pkProto.getP());
        BigInteger q = new BigInteger(pkProto.getQ());
        BigInteger g = new BigInteger(pkProto.getG());
        BigInteger y = new BigInteger(pkProto.getY());
        return makeDSAPublicKeyFromParams(p, q, g, y);
    }

    /**
     * Verify {@code msg} with {@code sig} using {@code pk}
     */
    public static boolean verifySigFromDSA(byte[] msg, byte[] sig, PublicKey pk) {
        try {
            Signature verifyalg = Signature.getInstance("DSA");
            verifyalg.initVerify(pk);
            verifyalg.update(msg);
            if (!verifyalg.verify(sig)) {
                TimerLogger.error("Failed to validate signature");
                TimerLogger.error("Sig was:\n" + Arrays.toString(sig));
                return false;
            }
            TimerLogger.error("Good Sig was:\n" + Arrays.toString(sig));
            return true;
        } catch (NoSuchAlgorithmException e) {
            TimerLogger.error("DSA is invalid for some reason.");
        } catch (InvalidKeyException e) {
            TimerLogger.error("The given DSA key to verify is invalid.");
        } catch (SignatureException e) {
            TimerLogger.error("The format of the dsa input is invalid: " + e.getMessage());
            TimerLogger.error("Sig was:\n" + Arrays.toString(sig));
        }
        return false;
    }

} //ends SignatureOps class
