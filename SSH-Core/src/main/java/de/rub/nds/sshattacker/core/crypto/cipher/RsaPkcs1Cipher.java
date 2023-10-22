/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaPkcs1Cipher extends AbstractCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    private Cipher cipher;

    private final Key key;

    public RsaPkcs1Cipher(Key key) {
        this.key = key;
    }

    @Override
    public byte[] encrypt(byte[] data) throws CryptoException {
        try {
            prepareCipher(Cipher.ENCRYPT_MODE);
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Could not encrypt data with RSA/ECB/PKCS1Padding.", e);
        }
    }

    @Override
    public byte[] encrypt(byte[] plainData, byte[] iv) throws CryptoException {
        throw new UnsupportedOperationException("Encryption with IV not supported.");
    }

    @Override
    public byte[] encrypt(byte[] plainData, byte[] iv, byte[] additionalAuthenticatedData)
            throws CryptoException {
        throw new UnsupportedOperationException("AEAD encryption not supported.");
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws CryptoException {
        try {
            prepareCipher(Cipher.DECRYPT_MODE);
            return cipher.doFinal(encryptedData);
        } catch (IllegalBlockSizeException e) {
            LOGGER.fatal("Encryption-Error: {}", e.getMessage());
            LOGGER.fatal(e);
            throw new CryptoException("Could not decrypt data with RSA/ECB/PKCS1Padding.", e);
        } catch (BadPaddingException e) {
            LOGGER.fatal("Possible Attack detected, bad Padding");
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] iv) throws CryptoException {
        throw new UnsupportedOperationException("Decryption with IV not supported.");
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] iv, byte[] additionalAuthenticatedData)
            throws CryptoException, AEADBadTagException {
        throw new UnsupportedOperationException("AEAD decryption not supported.");
    }

    @Override
    public EncryptionAlgorithm getAlgorithm() {
        return null;
    }

    private void prepareCipher(int mode) {
        try {
            Cipher cipher;
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(mode, key);
            this.cipher = cipher;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
            LOGGER.error("RSA PCKS1 Cipher creation failed with error: " + e);
        }
    }
}
