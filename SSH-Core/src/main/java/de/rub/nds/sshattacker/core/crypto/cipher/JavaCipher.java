/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithmFamily;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithmType;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class JavaCipher implements EncryptionCipher, DecryptionCipher {

    private final EncryptionAlgorithm algorithm;

    private byte[] iv;
    private final byte[] key;

    private Cipher encryptCipher;
    private Cipher decryptCipher;

    public JavaCipher(EncryptionAlgorithm algorithm, byte[] key) throws CryptoException {
        this(algorithm, key, null);
    }

    public JavaCipher(EncryptionAlgorithm algorithm, byte[] key, byte[] iv) throws CryptoException {
        this.algorithm = algorithm;
        this.key = key;
        this.iv = iv;
        initCiphers();
    }

    private void initCiphers() throws CryptoException {
        if (key.length != algorithm.getKeySize()) {
            throw new CryptoException(
                    "Could not initialize JavaCipher. Make sure the provided key size (provided: "
                            + key.length
                            + ") matches the key size of the algorithm (provided: "
                            + algorithm
                            + ")");
        }
        if (iv == null && algorithm.getType() != EncryptionAlgorithmType.STREAM) {
            throw new CryptoException(
                    "Could not initialize JavaCipher. Missing an IV while the encryption algorithm requires one.");
        }
        if (iv != null && iv.length != algorithm.getIVSize()) {
            throw new CryptoException(
                    "Could not initialize JavaCipher. Make sure the provided IV length (provided: "
                            + iv.length
                            + ") matches the block size of the algorithm (provided: "
                            + algorithm
                            + ")");
        }

        try {
            String keySpecAlgorithm =
                    EncryptionAlgorithmFamily.getFamilyForAlgorithm(algorithm).getJavaName();
            encryptCipher = Cipher.getInstance(algorithm.getJavaName());
            decryptCipher = Cipher.getInstance(algorithm.getJavaName());
            if (algorithm.getType() == EncryptionAlgorithmType.AEAD) {
                encryptCipher.init(
                        Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(key, keySpecAlgorithm),
                        new GCMParameterSpec(algorithm.getAuthTagSize() * 8, iv));
                decryptCipher.init(
                        Cipher.DECRYPT_MODE,
                        new SecretKeySpec(key, keySpecAlgorithm),
                        new GCMParameterSpec(algorithm.getAuthTagSize() * 8, iv));
            } else if (algorithm.getType() == EncryptionAlgorithmType.BLOCK) {
                encryptCipher.init(
                        Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(key, keySpecAlgorithm),
                        new IvParameterSpec(iv));
                decryptCipher.init(
                        Cipher.DECRYPT_MODE,
                        new SecretKeySpec(key, keySpecAlgorithm),
                        new IvParameterSpec(iv));
            } else {
                encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm));
                decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm));
            }

            // This branch is used to take care of ARCFOUR128 and ARCFOUR256 which skip the first
            // 1536 bytes of their keystream
            int keystreamDiscardLength = algorithm.getKeystreamInitialDiscardLength();
            if (keystreamDiscardLength > 0) {
                encryptCipher.update(new byte[keystreamDiscardLength]);
                decryptCipher.update(new byte[keystreamDiscardLength]);
            }
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidAlgorithmParameterException
                | InvalidKeyException e) {
            throw new CryptoException(
                    "Could not initialize JavaCipher. Did you forget to use UnlimitedStrengthEnabler / add BouncyCastleProvider?",
                    e);
        }
    }

    @Override
    public byte[] encrypt(byte[] data) throws CryptoException {
        try {
            // RFC 4253 Section 6.3
            // The encrypted data in all packets sent in one direction SHOULD be
            // considered a single data stream.  For example, initialization vectors
            // SHOULD be passed from the end of one packet to the beginning of the
            // next packet.
            return encryptCipher.update(data);
        } catch (IllegalStateException e) {
            throw new CryptoException("Could not encrypt data with " + algorithm.getJavaName(), e);
        }
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] additionalAuthenticatedData) throws CryptoException {
        if (algorithm.getType() != EncryptionAlgorithmType.AEAD) {
            throw new CryptoException(
                    "Provided additional authenticated data with a cipher of type "
                            + algorithm.getType());
        }
        encryptCipher.updateAAD(additionalAuthenticatedData);
        byte[] output;
        try {
            output = encryptCipher.doFinal(data);
        } catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Could not encrypt data with " + algorithm.getJavaName(), e);
        }
        incrementInvocationCounter();
        return output;
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws CryptoException {
        try {
            // RFC 4253 Section 6.3
            // The encrypted data in all packets sent in one direction SHOULD be
            // considered a single data stream.  For example, initialization vectors
            // SHOULD be passed from the end of one packet to the beginning of the
            // next packet.
            return decryptCipher.update(encryptedData);
        } catch (IllegalStateException e) {
            throw new CryptoException("Could not decrypt data with " + algorithm.getJavaName(), e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] additionalAuthenticatedData)
            throws CryptoException, AEADBadTagException {
        if (algorithm.getType() != EncryptionAlgorithmType.AEAD) {
            throw new CryptoException(
                    "Provided additional authenticated data with a cipher of type "
                            + algorithm.getType());
        }
        decryptCipher.updateAAD(additionalAuthenticatedData);
        byte[] output;
        try {
            output = decryptCipher.doFinal(encryptedData);
        } catch (IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Could not decrypt data with " + algorithm.getJavaName(), e);
        }

        incrementInvocationCounter();
        return output;
    }

    public EncryptionAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public byte[] getIV() {
        return iv;
    }

    @Override
    public void setIV(byte[] iv) throws CryptoException {
        this.iv = iv;
        initCiphers();
    }

    private void incrementInvocationCounter() throws CryptoException {
        byte[] fixed = Arrays.copyOfRange(iv, 0, 4);
        byte[] invocationCounter = Arrays.copyOfRange(iv, 4, 12);
        // TODO: Fix ArrayConverter.bytesToLong() implementation and handle invocation counter as
        // long
        invocationCounter = new BigInteger(invocationCounter).add(BigInteger.ONE).toByteArray();
        setIV(ArrayConverter.concatenate(fixed, invocationCounter));
    }
}
