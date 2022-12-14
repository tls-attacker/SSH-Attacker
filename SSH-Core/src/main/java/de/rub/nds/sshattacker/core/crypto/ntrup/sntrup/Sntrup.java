/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.kex.KeyEncapsulation;
import de.rub.nds.sshattacker.core.crypto.keys.CustomHybridPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomHybridPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.R3;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.RQ;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.Rounded;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.Short;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupCore;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupCoreValues;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupParameterSet;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Sntrup extends KeyEncapsulation {
    private static final Logger LOGGER = LogManager.getLogger();
    private SntrupParameterSet set;
    private CustomHybridPublicKey remotePublicKey;
    private SntrupCore core;

    private CustomKeyPair<CustomHybridPrivateKey, CustomHybridPublicKey> localKeyPair;
    private byte[] encryptedSharedSecret;

    private int ciphertextBytes;
    private int pubKBytes;
    private int smallBytes;
    private int hashBytes;

    private String algorithm;

    // For SNTRUP4591761 which was defined during round one some things works a
    // little bit different than for SNTRUP761
    private final boolean round1;

    public Sntrup(SntrupParameterSet set, boolean round1) {
        this.set = set;
        this.core = new SntrupCore(set);
        this.round1 = round1;
        calculateNumberOfBytes(set);
    }

    private void calculateNumberOfBytes(SntrupParameterSet set) {
        switch (set) {
            case KEM_SNTRUP_761:

                if (round1) {
                    ciphertextBytes = 1049;
                    pubKBytes = 1218;
                    hashBytes = 0;
                    algorithm = "SNTRUP4591761";
                } else {
                    pubKBytes = 1158;
                    ciphertextBytes = 1007;
                    hashBytes = 32;
                    algorithm = "SNTRUP761";
                }
                smallBytes = 191;

                break;
            default:
                throw new IllegalArgumentException("ParameterSet " + set + " is not supported.");
        }
    }

    private void encapsR1(byte[] pubK) {
        Short r = Short.createRandomShort(set);
        RQ h = RQ.decode(set, pubK);
        byte[] encR = r.encode();
        byte[] c = core.encrypt(r, h).encode();

        byte[] hashConfirm = sha512(encR);
        this.encryptedSharedSecret = ArrayConverter.concatenate(hashConfirm, c);
        this.sharedSecret = new BigInteger(hashConfirm);
    }

    private void encapsR2(byte[] pubK) {
        Short r = Short.createRandomShort(set);
        RQ h = RQ.decode(set, pubK);

        byte[] encR = r.encode();
        byte[] c = core.encrypt(r, h).encode();

        byte[] cache = hashPrefixedB(pubK, (byte) 4);
        byte[] hashencR = hashPrefixedB(encR, (byte) 3);
        byte[] hashConfirm = hashPrefixedB(ArrayConverter.concatenate(hashencR, cache), (byte) 2);

        this.encryptedSharedSecret = ArrayConverter.concatenate(c, hashConfirm);
        this.sharedSecret = new BigInteger(hashPrefixedB(ArrayConverter.concatenate(hashencR, encryptedSharedSecret), (byte) 1));
    }

    private void decapsR1(byte[] privK, byte[] ciphertext) {
        LOGGER.info("Cyphertext in decaps: " + ArrayConverter.bytesToHexString(ciphertext));

        Short f = Short.decode(set, Arrays.copyOfRange(privK, 0, smallBytes));
        R3 gInv = R3.decode(set, Arrays.copyOfRange(privK, smallBytes, 2 * smallBytes));
        RQ h = RQ.decode(
                set, Arrays.copyOfRange(privK, 2 * smallBytes, 2 * smallBytes + pubKBytes));

        Rounded c = Rounded.decode(set, Arrays.copyOfRange(ciphertext, 32, ciphertextBytes));
        Short rNew = core.decrypt(c, f, gInv);
        byte[] rNewEnc = rNew.encode();
        byte[] cNewEnc = core.encrypt(rNew, h).encode();

        byte[] hashConfirmNew = sha512(rNewEnc);
        byte[] ciphertextNew = ArrayConverter.concatenate(hashConfirmNew, cNewEnc);

        if (Arrays.equals(ciphertext, ciphertextNew)) {
            LOGGER.info("Successfully decapsulated the cyphertext. Calculate shared Secret now...");
            this.sharedSecret = new BigInteger(hashConfirmNew);
        } else {
            LOGGER.warn(
                    "Could not decapsulate the shared secret.");
        }
    }

    private void decapsR2(byte[] privK, byte[] ciphertext) {
        LOGGER.info("Cyphertext in decaps: " + ArrayConverter.bytesToHexString(ciphertext));

        Short f = Short.decode(set, Arrays.copyOfRange(privK, 0, smallBytes));
        R3 gInv = R3.decode(set, Arrays.copyOfRange(privK, smallBytes, 2 * smallBytes));
        RQ h = RQ.decode(
                set, Arrays.copyOfRange(privK, 2 * smallBytes, 2 * smallBytes + pubKBytes));

        Rounded c = Rounded.decode(set, Arrays.copyOfRange(ciphertext, 0, ciphertextBytes));
        byte[] rho = Arrays.copyOfRange(privK,
                2 * smallBytes + pubKBytes,
                2 * smallBytes + pubKBytes + smallBytes);

        byte[] cache = Arrays.copyOfRange(privK,
                2 * smallBytes + pubKBytes + smallBytes,
                2 * smallBytes + pubKBytes + smallBytes + hashBytes);

        Short rNew = core.decrypt(c, f, gInv);
        byte[] rNewEnc = rNew.encode();
        byte[] cNewEnc = core.encrypt(rNew, h).encode();

        byte[] hashRNewEnc = hashPrefixedB(rNewEnc, (byte) 3);
        byte[] hashConfirmNew = hashPrefixedB(ArrayConverter.concatenate(hashRNewEnc, cache), (byte) 2);
        byte[] ciphertextNew = ArrayConverter.concatenate(cNewEnc, hashConfirmNew);

        if (Arrays.equals(ciphertext, ciphertextNew)) {
            LOGGER.info("Successfully decapsulated the cyphertext. Calculate shared Secret now...");
            this.sharedSecret = new BigInteger(hashPrefixedB(ArrayConverter.concatenate(hashRNewEnc, ciphertext), (byte) 1));

        } else {
            LOGGER.warn(
                    "Could not decapsulate the shared secret.");

            this.sharedSecret = new BigInteger(rho);
        }
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

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes) {
        CustomHybridPrivateKey privK = new CustomHybridPrivateKey(privateKeyBytes, algorithm);
        CustomHybridPublicKey pubK = new CustomHybridPublicKey(publicKeyBytes, algorithm);
        localKeyPair = new CustomKeyPair<CustomHybridPrivateKey, CustomHybridPublicKey>(privK, pubK);
    }

    @Override
    public void generateLocalKeyPair() {
        SntrupCoreValues values = core.keyGenCore();

        byte[] encF = values.getF().encode();
        byte[] encV = values.getgInv().encode();
        byte roh[] = null;
        byte encH[] = null;
        CustomHybridPrivateKey privK;
        CustomHybridPublicKey pubK = new CustomHybridPublicKey(encH, algorithm);

        if (round1) {
            encH = values.getH().encode_old();
            privK = new CustomHybridPrivateKey(ArrayConverter.concatenate(encF, encV, encH), algorithm);
            pubK = new CustomHybridPublicKey(encH, algorithm);
        } else {
            encH = values.getH().encode();
            roh = values.getRoh().encode();
            privK = new CustomHybridPrivateKey(
                    ArrayConverter.concatenate(encF, encV, encH, roh, hashPrefixedB(encH, (byte) 4)), algorithm);

        }

        LOGGER.info("Private Key CustomSntrup: " + ArrayConverter.bytesToHexString(privK.getEncoded()));
        LOGGER.info("Public Key CustomSntrup: " + ArrayConverter.bytesToHexString(pubK.getEncoded()));

        this.localKeyPair = new CustomKeyPair<>(privK, pubK);

    }

    @Override
    public CustomKeyPair<? extends CustomPrivateKey, ? extends CustomPublicKey> getLocalKeyPair() {
        if (localKeyPair == null) {
            generateLocalKeyPair();
        }
        return localKeyPair;
    }

    @Override
    public CustomPublicKey getRemotePublicKey() {
        return remotePublicKey;
    }

    @Override
    public void setRemotePublicKey(byte[] remotePublicKeyBytes) {
        this.remotePublicKey = new CustomHybridPublicKey(remotePublicKeyBytes, algorithm);

    }

    @Override
    public void setSharedSecret(byte[] sharedSecretBytes) {
        this.sharedSecret = new BigInteger(sharedSecretBytes);
    }

    @Override
    public void generateSharedSecret() {
        if (localKeyPair == null) {
            generateLocalKeyPair();
        }

        if (round1) {
            encapsR1(localKeyPair.getPublic().getEncoded());
        } else {
            encapsR2(encryptedSharedSecret);
        }
    }

    @Override
    public void setEncryptedSharedSecret(byte[] encryptedSharedSecret) {
        this.encryptedSharedSecret = encryptedSharedSecret;
    }

    @Override
    public byte[] getEncryptedSharedSecret() {
        return this.encryptedSharedSecret;
    }

    @Override
    public byte[] encryptSharedSecret() {
        if (remotePublicKey == null) {
            LOGGER.warn("RemotePublicKey not set, return BigInteger.valueOf(0)");
            return new byte[0];
        }
        if (round1) {
            encapsR1(remotePublicKey.getEncoded());
        } else {
            encapsR2(remotePublicKey.getEncoded());
        }

        return this.encryptedSharedSecret;
    }

    @Override
    public void decryptSharedSecret() throws CryptoException {
        if (encryptedSharedSecret == null) {
            LOGGER.warn("encrypted shared secret not set, set shared secret to BigInteger.valueOf(0)");
            this.sharedSecret = BigInteger.valueOf(0);
            return;
        }
        decryptSharedSecret(encryptedSharedSecret);
    }

    @Override
    public void decryptSharedSecret(byte[] encryptedSharedSecret) throws CryptoException {
        if (localKeyPair == null) {
            LOGGER.warn("local key pair not set, set shared secret to BigInteger.valueOf(0)");
            this.sharedSecret = BigInteger.valueOf(0);
            return;
        }

        if (round1) {
            decapsR1(localKeyPair.getPrivate().getEncoded(), encryptedSharedSecret);
        } else {
            decapsR2(localKeyPair.getPrivate().getEncoded(), encryptedSharedSecret);
        }

    }
}
