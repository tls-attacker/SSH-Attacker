/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.sshattacker.attacks.pkcs1;

import com.google.common.primitives.Bytes;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.Bits;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.pqc.math.linearalgebra.BigEndianConversions;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

/**
 *
 *
 */
public class Pkcs1VectorGenerator {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Generates different encrypted PKCS1 vectors
     *
     * @param  publicKey The RSA public key
     * @return encrypted pkcs1Vectors
     */
    public static List<Pkcs1Vector> generatePkcs1Vectors(RSAPublicKey publicKey, int hashLength) {
        List<Pkcs1Vector> encryptedVectors =
            generatePlainPkcs1Vectors(publicKey.getModulus().bitLength(), hashLength);
        try {
            Cipher rsa = Cipher.getInstance("RSA/NONE/NoPadding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            // encrypt all the padded keys
            for (Pkcs1Vector vector : encryptedVectors) {
                byte[] encrypted = rsa.doFinal(vector.getPlainValue());
                vector.setEncryptedValue(encrypted);
            }
            return encryptedVectors;
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException
            | NoSuchPaddingException ex) {
            throw new ConfigurationException("The different PKCS#1 attack vectors could not be generated.", ex);
        }
    }

    /**
     *
     * @param  publicKey RSA public key
     * @return Correctly padded message
     */
    public static Pkcs1Vector generateCorrectPkcs1Vector(RSAPublicKey publicKey, int hashLength) {
        Pkcs1Vector encryptedVector = getPlainCorrect(publicKey.getModulus().bitLength(), hashLength);
        try {
            Cipher rsa = Cipher.getInstance("RSA/NONE/NoPadding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            // encrypt all the padded keys
            byte[] encrypted = rsa.doFinal(encryptedVector.getPlainValue());
            encryptedVector.setEncryptedValue(encrypted);
            return encryptedVector;
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException
            | NoSuchPaddingException ex) {
            throw new ConfigurationException("The PKCS#1 attack vectors could not be generated.", ex);
        }
    }

    /**
     * Generates different plain PKCS1 vectors
     *
     * @param publicKeyBitLength The length of the public key in bits
     * @param hashLength The length of the hash function's output in bits
     * @return pkcs1Vectors
     */
    public static List<Pkcs1Vector> generatePlainPkcs1Vectors(int publicKeyBitLength, int hashLength) {
        int sharedSecretByteLength = (publicKeyBitLength - 2 * hashLength - 49) / Bits.IN_A_BYTE;
        byte[] keyBytes = new byte[sharedSecretByteLength];
        Arrays.fill(keyBytes, (byte) 42);
        int publicKeyByteLength = publicKeyBitLength / Bits.IN_A_BYTE;

        // create plain padded keys
        List<Pkcs1Vector> pkcs1Vectors = new LinkedList<>();
        pkcs1Vectors.add(
            new Pkcs1Vector("Correctly formatted PKCS#1 Secret message", getPaddedKey(publicKeyByteLength, keyBytes)));
        pkcs1Vectors.add(new Pkcs1Vector("Wrong first byte (0x00 set to 0x17)",
            getEK_WrongFirstByte(publicKeyByteLength, keyBytes)));
        return pkcs1Vectors;
    }

    private static Pkcs1Vector getPlainCorrect(int publicKeyBitLength, int hashLength) {
        byte[] keyBytes = new byte[publicKeyBitLength - 2 * hashLength - 49];
        Arrays.fill(keyBytes, (byte) 42);
        int publicKeyByteLength = publicKeyBitLength / Bits.IN_A_BYTE;
        return new Pkcs1Vector("Correctly formatted PKCS#1 Secret message", getPaddedKey(publicKeyByteLength, keyBytes));
    }

    /**
     * Generates a validly padded message
     *
     * @param  rsaKeyLength
     *                      rsa key length in bytes
     * @param  sharedSecret
     *                      shared secret to be padded
     * @return              padded secret
     */
    private static byte[] getPaddedKey(int rsaKeyLength, byte[] sharedSecret) {
        try {
            return doOaepEncoding(sharedSecret, "SHA-256", rsaKeyLength);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.debug("Encoding error", e);
            return new byte[rsaKeyLength];
        }
    }

    //TODO: Generate invalid messages for Manger
    private static byte[] getEK_WrongFirstByte(int rsaKeyLength, byte[] symmetricKey) {
        byte[] key = getPaddedKey(rsaKeyLength, symmetricKey);
        key[0] = 23;
        LOGGER.debug("Generated a PKCS1 padded message with a wrong first byte: {}",
            ArrayConverter.bytesToHexString(key));
        return key;
    }

    /**
     * No instantiation needed, only one static method used
     */
    private Pkcs1VectorGenerator() {
    }

    /**
     * Encodes message using OAEP with digest hashInstance for a key of length keyLen
     * @param message Message to be encoded
     * @param hashInstance Name of hash to be used
     * @param keyLen Length of the public key
     * @return Encoded message
     * @throws NoSuchAlgorithmException if hashInstance does not exist
     */
    public static byte[] doOaepEncoding(byte[] message, String hashInstance, int keyLen) throws NoSuchAlgorithmException {

        byte[] result = new byte[keyLen];

        MessageDigest hash = MessageDigest.getInstance(hashInstance);
        int hashLen = hash.getDigestLength();

        // Step a: Generate label hash
        byte[] lHash;
        lHash = hash.digest(new byte[0]);

        // Step b: Generate padding string
        byte[] padding = new byte[keyLen - message.length - 2 * hashLen - 2];
        Arrays.fill(padding, (byte) 0);

        // Step c: Create data block
        byte[] dataBlock = new byte[keyLen - hashLen - 1];
        int index = 0;
        System.arraycopy(lHash, 0, dataBlock, index, lHash.length); // Start with label hash
        index += lHash.length;
        System.arraycopy(padding, 0, dataBlock, index, padding.length); // Add padding string
        index += padding.length;
        dataBlock[index] = (byte) 1; // Set separating 01
        index += 1;
        System.arraycopy(message, 0, dataBlock, index, message.length); // Finish by adding message

        // Step d: Generate random octet string seed of length hashLen
        byte[] seed = new byte[hashLen];
        new Random().nextBytes(seed);

        // Step e: Generate data block mask
        byte[] dataBlockMask = mgf1(seed, keyLen - hashLen - 1, hashInstance);

        // Step f: Mask data block
        byte[] maskedDataBlock = xor(dataBlock, dataBlockMask);

        // Step g: Generate seed mask
        byte[] seedMask = mgf1(maskedDataBlock, hashLen, hashInstance);

        // Step h: Mask seed
        byte[] maskedSeed = xor(seed, seedMask);

        // Step i: Create result message
        result[0] = (byte) 0; // First byte is 00
        System.arraycopy(maskedSeed, 0, result, 1, maskedSeed.length);
        System.arraycopy(maskedDataBlock, 0, result, maskedSeed.length + 1, maskedDataBlock.length);

        LOGGER.debug("Encoded message: " + Arrays.toString(result));
        return result;
    }

    /**
     * Decodes message using OAEP with digest hashInstance for a key of length keyLen
     * @param encodedMessage Message to be decoded
     * @param hashInstance Name of hash to be used
     * @param keyLen Length of the public key
     * @return Decoded message
     * @throws NoSuchAlgorithmException if hashInstance does not exist
     */
    public static byte[] doOaepDecoding(byte[] encodedMessage, String hashInstance, int keyLen) throws NoSuchAlgorithmException {
        // Prepare message digest
        MessageDigest hash = MessageDigest.getInstance(hashInstance);
        int hashLen = hash.getDigestLength();

        // Step a: label hash
        byte[] lHash;
        lHash = hash.digest(new byte[0]);

        // Step b: Separating the message
        byte y = encodedMessage[0];
        byte[] maskedSeed = Arrays.copyOfRange(
                encodedMessage,
                1,
                encodedMessage.length - (keyLen - hashLen - 1));
        byte[] maskedDataBlock = Arrays.copyOfRange(
                encodedMessage,
                encodedMessage.length - (keyLen - hashLen - 1) ,
                encodedMessage.length);

        // Step c: Seed mask
        byte[] seedMask = mgf1(maskedDataBlock, hashLen, hashInstance);

        // Step d: Get seed
        byte[] seed = xor(maskedSeed, seedMask);

        // Step e: Get data block mask
        byte[] dataBlockMask = mgf1(seed, keyLen - hashLen - 1, hashInstance);

        // Step f: Get data block:
        byte[] dataBlock = xor(maskedDataBlock, dataBlockMask);

        // Step g: Separate dataBlock
        byte[] lhashPrime = Arrays.copyOfRange(dataBlock, 0, hashLen);
        byte[] paddedMessage = Arrays.copyOfRange(dataBlock, hashLen, dataBlock.length);

        byte[] separator = new byte[1];
        separator[0] = (byte) 1;
        int indexOfSeparator = Bytes.indexOf(paddedMessage, separator);
        if (indexOfSeparator == -1) {
            throw new IndexOutOfBoundsException("Could not find separator in padded message");
        }

        byte[] padding = Arrays.copyOfRange(paddedMessage, 0, indexOfSeparator);
        byte[] message = Arrays.copyOfRange(paddedMessage, indexOfSeparator + 1, paddedMessage.length);

        LOGGER.debug("Retrieved message: " + Arrays.toString(message));
        return message;
    }

    /**
     *
     * @param seed Seed for the mask generation
     * @param maskLen Desired mask length in bytes
     * @param digestName Name of the digest to be used
     * @return generated mask
     */
    public static byte[] mgf1(byte[] seed, int maskLen, String digestName) throws NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance(digestName);
        int hashLen = digest.getDigestLength();
        // Step 1: Check length

        // Step 2: Initialize result T
        int maxIterations = (int) Math.ceil((double) maskLen / hashLen);
        byte[] result = new byte[maxIterations * hashLen];

        // Step 3: Iteratively create result
        for (int counter = 0; counter < maxIterations; counter++) {

            // Step a: Convert counter using I2OSP
            byte[] counterBytes = new byte[4];
            BigEndianConversions.I2OSP(counter, counterBytes, 0);

            // Step b: Concatenate hash of seed and counterBytes with intermediate result
            byte[] digestInput = new byte[seed.length + 4];
            System.arraycopy(seed, 0, digestInput, 0, seed.length);
            System.arraycopy(counterBytes, 0, digestInput, seed.length, counterBytes.length);
            byte[] digestOutput = digest.digest(digestInput);
            System.arraycopy(digestOutput, 0, result, counter * hashLen, hashLen);
        }

        // Result are first maskLen bytes
        return Arrays.copyOfRange(result, 0, maskLen);
    }

    /**
     * XORs two byte arrays
     * @param left First array
     * @param right Second array
     * @return Result of XOR operation
     */
    public static byte[] xor(byte[] left, byte[] right) {
        if (left == null || right == null)
            return null;
        if (left.length > right.length) {
            byte[] swap = left;
            left = right;
            right = swap;
        }

        // left.length is now <= right.length
        byte[] out = Arrays.copyOf(right, right.length);
        for (int i = 0; i < left.length; i++) {
            out[i] = (byte) ((left[i] & 0xFF) ^ (right[i] & 0xFF));
        }
        return out;
    }
}
