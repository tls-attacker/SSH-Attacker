/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithmFamily;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class JavaCipher extends AbstractCipher {

    private final EncryptionAlgorithm algorithm;
    private final byte[] key;
    private final boolean keepCipherState;
    private Cipher cipher;

    JavaCipher(EncryptionAlgorithm algorithm, byte[] key, boolean keepCipherState) {
        super();
        this.algorithm = algorithm;
        this.key = key;
        this.keepCipherState = keepCipherState;
    }

    @Override
    public byte[] encrypt(byte[] plainData) throws CryptoException {
        try {
            if (cipher == null) {
                cipher = Cipher.getInstance(algorithm.getJavaName());
                String keySpecAlgorithm =
                        EncryptionAlgorithmFamily.getFamilyForAlgorithm(algorithm).getJavaName();
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm));
                int keystreamDiscardLength = algorithm.getKeystreamInitialDiscardLength();
                if (keepCipherState && keystreamDiscardLength > 0) {
                    cipher.update(new byte[keystreamDiscardLength]);
                }
            }
            if (keepCipherState) {
                return cipher.update(plainData);
            } else {
                return cipher.doFinal(plainData);
            }
        } catch (IllegalStateException
                | IllegalBlockSizeException
                | BadPaddingException
                | NoSuchAlgorithmException
                | InvalidKeyException
                | NoSuchPaddingException
                | IllegalArgumentException ex) {
            throw new CryptoException(
                    "Could not encrypt data with: " + algorithm.getJavaName(), ex);
        }
    }

    @Override
    public byte[] encrypt(byte[] plainData, byte[] iv) throws CryptoException {
        IvParameterSpec encryptIv = new IvParameterSpec(iv);
        try {
            cipher = Cipher.getInstance(algorithm.getJavaName());
            String keySpecAlgorithm =
                    EncryptionAlgorithmFamily.getFamilyForAlgorithm(algorithm).getJavaName();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm), encryptIv);
            return cipher.doFinal(plainData);
        } catch (IllegalStateException
                | IllegalBlockSizeException
                | BadPaddingException
                | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException
                | InvalidKeyException
                | NoSuchPaddingException
                | IllegalArgumentException ex) {
            throw new CryptoException(
                    "Could not initialize JavaCipher. "
                            + "Did you forget to use UnlimitedStrengthEnabler/add BouncyCastleProvider?",
                    ex);
        }
    }

    @Override
    public byte[] encrypt(byte[] plainData, byte[] iv, byte[] additionalAuthenticatedData)
            throws CryptoException {
        GCMParameterSpec encryptIv = new GCMParameterSpec(algorithm.getAuthTagSize() * 8, iv);
        try {
            cipher = Cipher.getInstance(algorithm.getJavaName());
            String keySpecAlgorithm =
                    EncryptionAlgorithmFamily.getFamilyForAlgorithm(algorithm).getJavaName();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm), encryptIv);
            cipher.updateAAD(additionalAuthenticatedData);
            return cipher.doFinal(plainData);
        } catch (IllegalStateException
                | IllegalBlockSizeException
                | BadPaddingException
                | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException
                | InvalidKeyException
                | NoSuchPaddingException
                | IllegalArgumentException ex) {
            throw new CryptoException("Could not encrypt data with " + algorithm.getJavaName(), ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws CryptoException {
        try {
            if (cipher == null) {
                cipher = Cipher.getInstance(algorithm.getJavaName());
                String keySpecAlgorithm =
                        EncryptionAlgorithmFamily.getFamilyForAlgorithm(algorithm).getJavaName();
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm));
                int keystreamDiscardLength = algorithm.getKeystreamInitialDiscardLength();
                if (keepCipherState && keystreamDiscardLength > 0) {
                    cipher.update(new byte[keystreamDiscardLength]);
                }
            }
            if (keepCipherState) {
                return cipher.update(encryptedData);
            } else {
                return cipher.doFinal(encryptedData);
            }
        } catch (IllegalStateException
                | NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidKeyException
                | IllegalBlockSizeException
                | BadPaddingException ex) {
            throw new CryptoException("Could not decrypt data", ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] iv) throws CryptoException {
        IvParameterSpec decryptIv = new IvParameterSpec(iv);
        try {
            cipher = Cipher.getInstance(algorithm.getJavaName());
            String keySpecAlgorithm =
                    EncryptionAlgorithmFamily.getFamilyForAlgorithm(algorithm).getJavaName();
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm), decryptIv);
            return cipher.doFinal(encryptedData);
        } catch (IllegalStateException
                | IllegalBlockSizeException
                | BadPaddingException
                | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException
                | InvalidKeyException
                | NoSuchPaddingException ex) {
            throw new CryptoException("Could not decrypt data", ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] iv, byte[] additionalAuthenticatedData)
            throws CryptoException {
        GCMParameterSpec decryptIv = new GCMParameterSpec(algorithm.getAuthTagSize() * 8, iv);
        try {
            cipher = Cipher.getInstance(algorithm.getJavaName());
            String keySpecAlgorithm =
                    EncryptionAlgorithmFamily.getFamilyForAlgorithm(algorithm).getJavaName();
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keySpecAlgorithm), decryptIv);
            cipher.updateAAD(additionalAuthenticatedData);
            return cipher.doFinal(encryptedData);
        } catch (IllegalStateException
                | IllegalBlockSizeException
                | BadPaddingException
                | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException
                | InvalidKeyException
                | NoSuchPaddingException
                | IllegalArgumentException ex) {
            throw new CryptoException("Could not decrypt data", ex);
        }
    }

    @Override
    public EncryptionAlgorithm getAlgorithm() {
        return algorithm;
    }
}
