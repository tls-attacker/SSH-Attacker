/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.R3;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.RQ;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.Rounded;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.Short;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupCore;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupKeyPairCore;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupParameterSet;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupPrivKeyCore;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupPubKeyCore;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Sntrup {
    private static final Logger LOGGER = LogManager.getLogger();
    private SntrupParameterSet set;
    private SntrupCore core;
    private byte[] cyphertext;
    private byte[] sharedSecret;

    private int cyphertextBytes; 
    private int pubKBytes;
    private int smallBytes;

    public Sntrup(SntrupParameterSet set) {
        this.set = set;
        this.core = new SntrupCore(set);
        calculateNumberOfBytes(set);
    }

    private void calculateNumberOfBytes(SntrupParameterSet set) {
        switch (set) {
            case KEM_SNTRUP_761:
                cyphertextBytes =1007;
                pubKBytes = 1158;
                smallBytes = 191;
                break;
            default:
                throw new IllegalArgumentException("ParameterSet " + set +" is not supported.");
        }
    }

    public byte[] getSharedSecret() {
        return this.sharedSecret;
    }

    public byte[] getCyphertext() {
        return this.cyphertext;
    }

    public SntrupKeyPair keyGen() {
        SntrupKeyPairCore keyPairC = core.keyGenCore();
        byte[] encH = keyPairC.getPubKey().getH().encode();
        byte[] encF = keyPairC.getPrivKey().getF().encode();
        byte[] encV = keyPairC.getPrivKey().getgInv().encode();
        byte[] roh = generateRandomEnc();
        byte[] privKbytes = ArrayConverter.concatenate(encF, encV, encH, roh, hashPrefixedB(encH, (byte) 4));

        SntrupPrivateKey privK = new SntrupPrivateKey(privKbytes);
        SntrupPublicKey pubK = new SntrupPublicKey(encH);
        LOGGER.info("Private Key CustomSntrup: " + ArrayConverter.bytesToHexString(privKbytes));
        LOGGER.info("Public Key CustomSntrup: " + ArrayConverter.bytesToHexString(encH));
        return new SntrupKeyPair(pubK, privK);
    }

    public void encaps(byte[] pubK) {
        Short r = Short.createRandomShort(set);
        byte[] encR = r.encode();
        RQ h = RQ.decode(set, pubK);
        byte[] c = core.encrypt(r, new SntrupPubKeyCore(h)).encode();
        byte[] cache = hashPrefixedB(pubK, (byte) 4);
        byte[] hashencR = hashPrefixedB(encR, (byte) 3);
        byte[] hashConfirm = hashPrefixedB(ArrayConverter.concatenate(hashencR, cache), (byte) 2);

        this.cyphertext = ArrayConverter.concatenate(c, hashConfirm);
        this.sharedSecret = hashPrefixedB(ArrayConverter.concatenate(hashencR, cyphertext), (byte) 1);
    }

    public byte[] decaps(byte[] privK, byte[] cyphertext) {
        LOGGER.info("Cyphertext in decaps: " + ArrayConverter.bytesToHexString(cyphertext));
        Rounded c = Rounded.decode(set, Arrays.copyOfRange(cyphertext, 0, cyphertextBytes));
        Short f = Short.decode(set, Arrays.copyOfRange(privK, 0, smallBytes));
        R3 gInv = R3.decode(set, Arrays.copyOfRange(privK, smallBytes, 2 * smallBytes));
        RQ h = RQ.decode(set, Arrays.copyOfRange(privK, 2 * smallBytes, 2 * smallBytes + pubKBytes));
        byte[] rho = Arrays.copyOfRange(privK, 2 * smallBytes + pubKBytes,
                2 * smallBytes + pubKBytes + (int) Math.ceil(set.getP() / 4.0));

        
        SntrupPrivKeyCore privKCore = new SntrupPrivKeyCore(f, gInv);
        Short rNew = core.decrypt(c, privKCore);
        byte[] rNewEnc = rNew.encode();
        byte[] cNewEnc = core.encrypt(rNew, new SntrupPubKeyCore(h)).encode();
        byte[] cache = hashPrefixedB(h.encode(), (byte) 4);
        byte[] hashRNewEnc = hashPrefixedB(rNewEnc, (byte) 3);
        byte[] hashConfirmNew = hashPrefixedB(ArrayConverter.concatenate(hashRNewEnc, cache), (byte) 2);
        byte[] cyphertextNew = ArrayConverter.concatenate(cNewEnc, hashConfirmNew);
       
        if (Arrays.equals(cyphertext, cyphertextNew)) {
            LOGGER.info("Successfully decapsulated the cyphertext. Calculate shared Secret now...");
            this.sharedSecret = hashPrefixedB(ArrayConverter.concatenate(hashRNewEnc, cyphertext), (byte) 1);
        } else {
            LOGGER.warn("Could not decapsulate the shared secret, try to return return rho instead");
            this.sharedSecret = rho;
        }
        return this.sharedSecret;
    }

    private byte[] generateRandomEnc() {
        byte[] roh = new byte[(int) Math.ceil(set.getP() / 4.0)];
        Random rand = new Random();
        for (int i = 0; i < roh.length; i++) {
            roh[i] = (byte)rand.nextInt(256);
        }
        return roh;
    }

    private byte[] sha512(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] hashedBytes = md.digest(bytes);

            return Arrays.copyOfRange(hashedBytes, 0, 32);

        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("Could not create the hash, return an empty array instead");
            return new byte[32];
        }

    }

    private byte[] hashPrefixedB(byte[] bytes, byte b) {
        byte[] bByte = { b };
        return sha512(ArrayConverter.concatenate(bByte, bytes));
    }
}
