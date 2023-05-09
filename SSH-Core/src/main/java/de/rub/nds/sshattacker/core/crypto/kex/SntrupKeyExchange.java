/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.PQKemNames;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPQKemPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPQKemPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.R3;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.RQ;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.Rounded;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.Short;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupCore;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupCoreValues;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupParameterSet;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

@SuppressWarnings("StandardVariableNames")
public class SntrupKeyExchange extends KeyEncapsulation {
    private static final Logger LOGGER = LogManager.getLogger();
    private final SntrupParameterSet set;
    private CustomPQKemPublicKey remotePublicKey;
    private final SntrupCore core;

    private CustomKeyPair<CustomPQKemPrivateKey, CustomPQKemPublicKey> localKeyPair;
    private byte[] encryptedSharedSecret;

    private final PQKemNames kemName;

    public SntrupKeyExchange(PQKemNames kemName) {
        super();
        this.kemName = kemName;
        switch (kemName) {
            case SNTRUP4591761:
                set = SntrupParameterSet.KEM_SNTRUP_4591761;
                break;
            case SNTRUP761:
                set = SntrupParameterSet.KEM_SNTRUP_761;
                break;
            default:
                throw new IllegalArgumentException(
                        getClass().getName() + " does not support " + kemName.getName());
        }
        core = new SntrupCore(set);
    }

    private void encapsR1(byte[] pubK) {
        Short r = Short.createRandomShort(set);
        RQ h = RQ.decode_old(set, pubK);
        byte[] encR = r.encode();
        byte[] c = SntrupCore.encrypt(r, h).encode_old();

        byte[] hash = sha512(encR);
        encryptedSharedSecret = ArrayConverter.concatenate(Arrays.copyOfRange(hash, 0, 32), c);
        sharedSecret = Arrays.copyOfRange(hash, 32, 64);
    }

    private void encapsR2(byte[] pubK) {
        Short r = Short.createRandomShort(set);
        RQ h = RQ.decode(set, pubK);

        byte[] encR = r.encode();
        byte[] c = SntrupCore.encrypt(r, h).encode();

        byte[] cache = hashPrefixedB(pubK, (byte) 4);
        byte[] hashencR = hashPrefixedB(encR, (byte) 3);
        byte[] hashConfirm = hashPrefixedB(ArrayConverter.concatenate(hashencR, cache), (byte) 2);

        encryptedSharedSecret = ArrayConverter.concatenate(c, hashConfirm);
        sharedSecret =
                hashPrefixedB(
                        ArrayConverter.concatenate(hashencR, encryptedSharedSecret), (byte) 1);
    }

    private void decapsR1(byte[] privK, byte[] ciphertext) {
        encryptedSharedSecret = ciphertext;
        Short f = Short.decode(set, Arrays.copyOfRange(privK, 0, set.getEncodedSmallLength()));
        R3 gInv =
                R3.decode(
                        set,
                        Arrays.copyOfRange(
                                privK,
                                set.getEncodedSmallLength(),
                                2 * set.getEncodedSmallLength()));
        RQ h =
                RQ.decode_old(
                        set,
                        Arrays.copyOfRange(
                                privK,
                                2 * set.getEncodedSmallLength(),
                                2 * set.getEncodedSmallLength() + set.getEncodedPublicKeyLength()));

        Rounded c =
                Rounded.decode_old(
                        set, Arrays.copyOfRange(ciphertext, 32, set.getEncodedCiphertextLength()));
        Short rNew = core.decrypt(c, f, gInv);
        byte[] rNewEnc = rNew.encode();
        byte[] cNewEnc = SntrupCore.encrypt(rNew, h).encode_old();

        byte[] hashNew = sha512(rNewEnc);
        byte[] ciphertextNew =
                ArrayConverter.concatenate(Arrays.copyOfRange(hashNew, 0, 32), cNewEnc);

        if (Arrays.equals(ciphertext, ciphertextNew)) {
            LOGGER.info("Successfully decapsulated the cyphertext. Calculate shared Secret now...");
            sharedSecret = Arrays.copyOfRange(hashNew, 32, 64);
            encryptedSharedSecret = ciphertext;
        } else {
            LOGGER.warn("Could not decapsulate the shared secret.");
        }
    }

    private void decapsR2(byte[] privK, byte[] ciphertext) {
        encryptedSharedSecret = ciphertext;
        Short f = Short.decode(set, Arrays.copyOfRange(privK, 0, set.getEncodedSmallLength()));
        R3 gInv =
                R3.decode(
                        set,
                        Arrays.copyOfRange(
                                privK,
                                set.getEncodedSmallLength(),
                                2 * set.getEncodedSmallLength()));
        RQ h =
                RQ.decode(
                        set,
                        Arrays.copyOfRange(
                                privK,
                                2 * set.getEncodedSmallLength(),
                                2 * set.getEncodedSmallLength() + set.getEncodedPublicKeyLength()));

        Rounded c =
                Rounded.decode(
                        set, Arrays.copyOfRange(ciphertext, 0, set.getEncodedCiphertextLength()));
        byte[] rho =
                Arrays.copyOfRange(
                        privK,
                        2 * set.getEncodedSmallLength() + set.getEncodedPublicKeyLength(),
                        2 * set.getEncodedSmallLength()
                                + set.getEncodedPublicKeyLength()
                                + set.getEncodedSmallLength());

        byte[] cache =
                Arrays.copyOfRange(
                        privK,
                        2 * set.getEncodedSmallLength()
                                + set.getEncodedPublicKeyLength()
                                + set.getEncodedSmallLength(),
                        2 * set.getEncodedSmallLength()
                                + set.getEncodedPublicKeyLength()
                                + set.getEncodedSmallLength()
                                + set.getHashLength());

        Short rNew = core.decrypt(c, f, gInv);
        byte[] rNewEnc = rNew.encode();
        byte[] cNewEnc = SntrupCore.encrypt(rNew, h).encode();

        byte[] hashRNewEnc = hashPrefixedB(rNewEnc, (byte) 3);
        byte[] hashConfirmNew =
                hashPrefixedB(ArrayConverter.concatenate(hashRNewEnc, cache), (byte) 2);
        byte[] ciphertextNew = ArrayConverter.concatenate(cNewEnc, hashConfirmNew);

        if (Arrays.equals(ciphertext, ciphertextNew)) {
            LOGGER.info("Successfully decapsulated the cyphertext. Calculate shared Secret now...");

            sharedSecret =
                    hashPrefixedB(ArrayConverter.concatenate(hashRNewEnc, ciphertext), (byte) 1);

        } else {
            LOGGER.warn("Could not decapsulate the shared secret.");

            sharedSecret = rho;
        }
    }

    private static byte[] sha512(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            return md.digest(bytes);

        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("Could not create the hash, return an empty array instead");
            return new byte[64];
        }
    }

    private static byte[] hashPrefixedB(byte[] bytes, byte b) {
        byte[] bByte = {b};
        return Arrays.copyOfRange(sha512(ArrayConverter.concatenate(bByte, bytes)), 0, 32);
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes) {
        CustomPQKemPrivateKey privK = new CustomPQKemPrivateKey(privateKeyBytes, kemName);
        CustomPQKemPublicKey pubK = new CustomPQKemPublicKey(publicKeyBytes, kemName);
        localKeyPair = new CustomKeyPair<>(privK, pubK);
    }

    @Override
    public void generateLocalKeyPair() {
        SntrupCoreValues values = core.keyGenCore();
        byte[] encF = values.getF().encode();
        byte[] encV = values.getgInv().encode();
        byte[] encH;

        CustomPQKemPrivateKey privK;
        CustomPQKemPublicKey pubK;

        if (set == SntrupParameterSet.KEM_SNTRUP_4591761) {
            encH = values.getH().encode_old();
            pubK = new CustomPQKemPublicKey(values.getH().encode_old(), kemName);
            privK =
                    new CustomPQKemPrivateKey(
                            ArrayConverter.concatenate(encF, encV, encH), kemName);
        } else {
            encH = values.getH().encode();
            byte[] roh = values.getRoh().encode();
            pubK = new CustomPQKemPublicKey(values.getH().encode(), kemName);
            privK =
                    new CustomPQKemPrivateKey(
                            ArrayConverter.concatenate(
                                    encF, encV, encH, roh, hashPrefixedB(encH, (byte) 4)),
                            kemName);
        }

        localKeyPair = new CustomKeyPair<>(privK, pubK);
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
        remotePublicKey = new CustomPQKemPublicKey(remotePublicKeyBytes, kemName);
    }

    @Override
    public void setSharedSecret(byte[] sharedSecretBytes) {
        sharedSecret = sharedSecretBytes;
    }

    @Override
    public void generateSharedSecret() {
        if (localKeyPair == null) {
            generateLocalKeyPair();
        }

        if (set == SntrupParameterSet.KEM_SNTRUP_4591761) {
            encapsR1(localKeyPair.getPublicKey().getEncoded());
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
        return encryptedSharedSecret;
    }

    @Override
    public byte[] encryptSharedSecret() {
        if (remotePublicKey == null) {
            LOGGER.warn("RemotePublicKey not set, return BigInteger.valueOf(0)");
            return new byte[0];
        }
        if (set == SntrupParameterSet.KEM_SNTRUP_4591761) {
            encapsR1(remotePublicKey.getEncoded());
        } else {
            encapsR2(remotePublicKey.getEncoded());
        }

        return encryptedSharedSecret;
    }

    @Override
    public void decryptSharedSecret() {
        if (encryptedSharedSecret == null) {
            LOGGER.warn("encrypted shared secret not set, set shared secret to byte[] {0}");
            sharedSecret = new byte[] {0};
            return;
        }
        decryptSharedSecret(encryptedSharedSecret);
    }

    @Override
    public void decryptSharedSecret(byte[] encryptedSharedSecret) {
        if (localKeyPair == null) {
            LOGGER.warn("local key pair not set, set shared secret to byte[] {0}");
            sharedSecret = new byte[] {0};
            return;
        }

        if (set == SntrupParameterSet.KEM_SNTRUP_4591761) {
            decapsR1(localKeyPair.getPrivateKey().getEncoded(), encryptedSharedSecret);
        } else {
            decapsR2(localKeyPair.getPrivateKey().getEncoded(), encryptedSharedSecret);
        }
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes) {
        throw new NotImplementedException("The method is not supported.");
    }
}
