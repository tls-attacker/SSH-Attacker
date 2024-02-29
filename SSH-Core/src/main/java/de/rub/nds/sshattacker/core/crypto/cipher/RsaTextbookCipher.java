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
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.math.BigInteger;
import java.security.Key;
import javax.crypto.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaTextbookCipher extends AbstractCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    private Cipher cipher;

    private final Key key;

    private BigInteger publicExponent;
    private BigInteger modulus;
    private BigInteger privateExponent;

    public RsaTextbookCipher(Key key) {
        this.key = key;
    }

    /**
     * Encrypts the given byte array using RSA encryption.
     *
     * @param plainData the byte array to be encrypted
     * @return the encrypted byte array
     * @throws CryptoException if an error occurs during encryption
     */
    @Override
    public byte[] encrypt(byte[] plainData) throws CryptoException {
        prepareCipher(Cipher.ENCRYPT_MODE);
        String dataString = ArrayConverter.bytesToRawHexString(plainData);
        BigInteger dataBigInt = new BigInteger(dataString, 16);
        BigInteger encryptedBigInt = dataBigInt.modPow(publicExponent, modulus);
        return ArrayConverter.bigIntegerToByteArray(encryptedBigInt);
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

    /**
     * Decrypts the given byte array using RSA decryption.
     *
     * @param encryptedData the byte array to be decrypted
     * @return the decrypted byte array
     * @throws CryptoException if an error occurs during decryption
     */
    @Override
    public byte[] decrypt(byte[] encryptedData) throws CryptoException {
        prepareCipher(Cipher.DECRYPT_MODE);
        String dataString = ArrayConverter.bytesToRawHexString(encryptedData);
        BigInteger dataBigInt = new BigInteger(dataString, 16);
        BigInteger decryptedBigInt = dataBigInt.modPow(privateExponent, modulus);
        return ArrayConverter.bigIntegerToByteArray(decryptedBigInt);
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

    /**
     * Prepares the RSA-Cipher for encryption or decryption mode.
     *
     * @param mode the mode of the Cipher object. Use Cipher.ENCRYPT_MODE for encryption and
     *     Cipher.DECRYPT_MODE for decryption.
     */
    private void prepareCipher(int mode) {
        if (key instanceof CustomRsaPublicKey && mode == Cipher.ENCRYPT_MODE) {
            CustomRsaPublicKey publicKey = (CustomRsaPublicKey) key;
            modulus = publicKey.getModulus();
            publicExponent = publicKey.getPublicExponent();
        } else if (key instanceof CustomRsaPrivateKey && mode == Cipher.DECRYPT_MODE) {
            CustomRsaPrivateKey privateKey = (CustomRsaPrivateKey) key;
            modulus = privateKey.getModulus();
            privateExponent = privateKey.getPrivateExponent();
        } else {
            LOGGER.error("Not a valid key or not the correct key for this mode");
        }
    }
}
