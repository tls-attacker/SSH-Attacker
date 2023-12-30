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
    private final Cipher encCipher1, encCipher2, encCipher3;
    private final Cipher decCipher1, decCipher2, decCipher3;

    public TribleDESCipher(byte[] key) {

        LOGGER.debug("Init with key {}", ArrayConverter.bytesToHexString(key));

        IvParameterSpec encIvSpec1 = new IvParameterSpec(new byte[8]);
        IvParameterSpec encIvSpec2 = new IvParameterSpec(new byte[8]);
        IvParameterSpec encIvSpec3 = new IvParameterSpec(new byte[8]);
        IvParameterSpec decIvSpec1 = new IvParameterSpec(new byte[8]);
        IvParameterSpec decIvSpec2 = new IvParameterSpec(new byte[8]);
        IvParameterSpec decIvSpec3 = new IvParameterSpec(new byte[8]);

        this.key1 = new byte[8];
        this.key2 = new byte[8];
        this.key3 = new byte[8];

        System.arraycopy(key, 0, this.key1, 0, 8);
        System.arraycopy(key, 8, this.key2, 0, 8);
        System.arraycopy(key, 16, this.key3, 0, 8);

        try {
            this.encCipher1 = Cipher.getInstance("DES/CBC/NoPadding");
            this.encCipher2 = Cipher.getInstance("DES/CBC/NoPadding");
            this.encCipher3 = Cipher.getInstance("DES/CBC/NoPadding");

            encCipher1.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.key1, "DES"), encIvSpec1);
            encCipher2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.key2, "DES"), encIvSpec2);
            encCipher3.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.key3, "DES"), encIvSpec3);

            this.decCipher1 = Cipher.getInstance("DES/CBC/NoPadding");
            this.decCipher2 = Cipher.getInstance("DES/CBC/NoPadding");
            this.decCipher3 = Cipher.getInstance("DES/CBC/NoPadding");

            decCipher1.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.key3, "DES"), decIvSpec1);
            decCipher2.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(this.key2, "DES"), decIvSpec2);
            decCipher3.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.key1, "DES"), decIvSpec3);

        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidAlgorithmParameterException
                | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] encrypt(byte[] plainData) throws CryptoException {
        return encrypt(plainData, new byte[8]);
    }

    @Override
    public byte[] encrypt(byte[] plainData, byte[] iv) throws CryptoException {
        // iv = new byte[8];
        LOGGER.info(
                "Encrypting 3DES with data: {} with iv {}",
                ArrayConverter.bytesToHexString(plainData),
                ArrayConverter.bytesToHexString(iv));

        LOGGER.debug("Encryption with key {}", ArrayConverter.bytesToHexString(this.key1));
        LOGGER.debug("Encryption with key {}", ArrayConverter.bytesToHexString(this.key2));
        LOGGER.debug("Encryption with key {}", ArrayConverter.bytesToHexString(this.key3));

        byte[] enc1 = encCipher1.update(plainData);
        byte[] enc2 = encCipher2.update(enc1);
        byte[] enc3 = encCipher3.update(enc2);
        LOGGER.info("Resulting in encrypted ata: {}", ArrayConverter.bytesToHexString(enc3));
        return enc3;
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
        // iv = new byte[8];
        LOGGER.info(
                "Decrypting 3DES with data: {} with iv {}",
                ArrayConverter.bytesToHexString(encryptedData),
                ArrayConverter.bytesToHexString(iv));

        LOGGER.debug("Decryption with key {}", ArrayConverter.bytesToHexString(this.key1));
        LOGGER.debug("Decryption with key {}", ArrayConverter.bytesToHexString(this.key2));
        LOGGER.debug("Decryption with key {}", ArrayConverter.bytesToHexString(this.key3));

        byte[] enc1 = decCipher1.update(encryptedData);
        byte[] enc2 = decCipher2.update(enc1);
        byte[] enc3 = decCipher3.update(enc2);
        LOGGER.info("Resulting in decrypted data: {}", ArrayConverter.bytesToHexString(enc3));
        return enc3;
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
