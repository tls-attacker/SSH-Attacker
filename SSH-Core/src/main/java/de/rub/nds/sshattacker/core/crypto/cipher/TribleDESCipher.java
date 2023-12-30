/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class TribleDESCipher extends AbstractCipher {

    private static final Logger LOGGER = LogManager.getLogger();
    private final byte[] key1, key2, key3;
    private final Cipher cipher1, cipher2, cipher3;

    public TribleDESCipher(byte[] key) {

        LOGGER.debug("Init with key {}", ArrayConverter.bytesToHexString(key));

        this.key1 = new byte[8];
        this.key2 = new byte[8];
        this.key3 = new byte[8];

        System.arraycopy(key, 0, this.key1, 0, 8);
        System.arraycopy(key, 8, this.key2, 0, 8);
        System.arraycopy(key, 16, this.key3, 0, 8);

        try {
            this.cipher1 = Cipher.getInstance("DES/CBC/NoPadding");
            this.cipher2 = Cipher.getInstance("DES/CBC/NoPadding");
            this.cipher3 = Cipher.getInstance("DES/CBC/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] encrypt(byte[] plainData) throws CryptoException {
        return encrypt(plainData, new byte[8]);
    }

    @Override
    public byte[] encrypt(byte[] plainData, byte[] iv) throws CryptoException {
        LOGGER.info(
                "Encrypting 3DES with data: {} with iv {}",
                ArrayConverter.bytesToHexString(plainData),
                iv);
        IvParameterSpec decryptIv = new IvParameterSpec(iv);
        try {
            LOGGER.debug("Encryption with key {}", ArrayConverter.bytesToHexString(this.key1));
            LOGGER.debug("Encryption with key {}", ArrayConverter.bytesToHexString(this.key2));
            LOGGER.debug("Encryption with key {}", ArrayConverter.bytesToHexString(this.key3));

            cipher1.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.key1, "DES"), decryptIv);
            cipher2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.key2, "DES"), decryptIv);
            cipher3.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.key3, "DES"), decryptIv);

            byte[] enc1 = cipher1.doFinal(plainData);
            byte[] enc2 = cipher2.doFinal(enc1);
            byte[] enc3 = cipher3.doFinal(enc2);
            LOGGER.info("Resulting in encrypted ata: {}", ArrayConverter.bytesToHexString(enc3));
            return enc3;

        } catch (InvalidKeyException
                | InvalidAlgorithmParameterException
                | IllegalBlockSizeException
                | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] encrypt(byte[] plainData, byte[] iv, byte[] additionalAuthenticatedData)
            throws CryptoException {
        throw new UnsupportedOperationException("TribleDES does not support Authentication");
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws CryptoException {
        return decrypt(encryptedData, new byte[8]);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] iv) throws CryptoException {
        IvParameterSpec decryptIv = new IvParameterSpec(iv);
        LOGGER.info(
                "Decrypting 3DES with data: {} with iv {}",
                ArrayConverter.bytesToHexString(encryptedData),
                iv);
        try {
            cipher1.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.key3, "DES"), decryptIv);
            cipher2.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.key2, "DES"), decryptIv);
            cipher3.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.key1, "DES"), decryptIv);

            byte[] enc1 = cipher1.doFinal(encryptedData);
            byte[] enc2 = cipher2.doFinal(enc1);
            byte[] enc3 = cipher3.doFinal(enc2);
            LOGGER.info("Resulting in decrypted data: {}", ArrayConverter.bytesToHexString(enc3));
            return enc3;

        } catch (InvalidKeyException
                | InvalidAlgorithmParameterException
                | IllegalBlockSizeException
                | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] iv, byte[] additionalAuthenticatedData)
            throws CryptoException, AEADBadTagException {
        throw new UnsupportedOperationException("TribleDES does not support Authentication");
    }

    @Override
    public EncryptionAlgorithm getAlgorithm() {
        return EncryptionAlgorithm.TRIPLE_DES_CBC;
    }
}
