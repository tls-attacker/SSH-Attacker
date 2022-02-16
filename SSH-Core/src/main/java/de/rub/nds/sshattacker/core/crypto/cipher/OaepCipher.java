/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.*;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class OaepCipher implements EncryptionCipher, DecryptionCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    private Cipher cipher;

    private final Key key;
    private final String cipherInstanceName;
    private final String hashFunctionName;
    private final String maskGenerationFunctionName;

    public OaepCipher(
            Key key,
            String cipherInstanceName,
            String hashFunctionName,
            String maskGenerationFunctionName) {
        this.key = key;
        this.cipherInstanceName = cipherInstanceName;
        this.hashFunctionName = hashFunctionName;
        this.maskGenerationFunctionName = maskGenerationFunctionName;
    }

    @Override
    public byte[] encrypt(byte[] data) throws CryptoException {
        try {
            prepareCipher(Cipher.ENCRYPT_MODE);
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException(
                    String.format("Could not encrypt data with %s.", cipherInstanceName), e);
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
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException(
                    String.format("Could not decrypt data with %s.", cipherInstanceName), e);
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
            cipher = Cipher.getInstance(cipherInstanceName);
            OAEPParameterSpec spec =
                    new OAEPParameterSpec(
                            hashFunctionName,
                            maskGenerationFunctionName,
                            new MGF1ParameterSpec(hashFunctionName),
                            PSource.PSpecified.DEFAULT);
            cipher.init(mode, key, spec);
            this.cipher = cipher;
        } catch (NoSuchPaddingException
                | NoSuchAlgorithmException
                | InvalidKeyException
                | InvalidAlgorithmParameterException e) {
            LOGGER.error("OAEP Cipher creation failed with error: " + e);
        }
    }
}
