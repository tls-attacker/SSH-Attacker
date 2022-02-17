package de.rub.nds.sshattacker.attacks.pkcs1.util;

import com.google.common.primitives.Bytes;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.pqc.math.linearalgebra.BigEndianConversions;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

/**
 * Utility class for performing raw OAEP encoding/decoding of messages according to PKCS#1 (RFC 8017)
 * It implements OAEP encoding and decoding, mask generation function MGF1 and xor for byte arrays
 */
public class OaepConverter {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Encodes message using OAEP with digest hashInstance for a key of length keyLen
     * @param message Message to be encoded
     * @param hashInstance Name of hash to be used
     * @param keyLen Length of the public key
     * @return Encoded message
     * @throws NoSuchAlgorithmException if hashInstance does not exist
     */
    public static byte[] doOaepEncoding(byte[] message, String hashInstance, int keyLen) throws NoSuchAlgorithmException {

        ByteBuffer result = ByteBuffer.allocate(keyLen);

        MessageDigest hash = MessageDigest.getInstance(hashInstance);
        int hashLen = hash.getDigestLength();

        // Step a: Generate label hash
        byte[] lHash = hash.digest(new byte[0]);

        // Step b: Generate padding string
        byte[] padding = new byte[keyLen - message.length - 2 * hashLen - 2];
        Arrays.fill(padding, (byte) 0);

        // Step c: Create data block
        ByteBuffer dataBlock = ByteBuffer.allocate(keyLen - hashLen - 1);
        dataBlock.put(lHash);
        dataBlock.put(padding);
        dataBlock.put((byte) 1); // 01 byte separating padding from message
        dataBlock.put(message);

        // Step d: Generate random octet string seed of length hashLen
        byte[] seed = new byte[hashLen];
        new Random().nextBytes(seed);

        // Step e: Generate data block mask
        byte[] dataBlockMask = mgf1(seed, keyLen - hashLen - 1, hashInstance);

        // Step f: Mask data block
        byte[] maskedDataBlock = xor(dataBlock.array(), dataBlockMask);

        // Step g: Generate seed mask
        byte[] seedMask = mgf1(maskedDataBlock, hashLen, hashInstance);

        // Step h: Mask seed
        byte[] maskedSeed = xor(seed, seedMask);

        // Step i: Create result message
        result.put((byte) 0); // Set initial zero byte
        result.put(maskedSeed);
        result.put(maskedDataBlock);

        LOGGER.debug("Encoded message: " + Arrays.toString(result.array()));
        return result.array();
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
        byte[] lHash = hash.digest(new byte[0]);

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
        ByteBuffer result = ByteBuffer.allocate(maxIterations * hashLen);

        // Step 3: Iteratively create result
        for (int counter = 0; counter < maxIterations; counter++) {

            // Step a: Convert counter using I2OSP
            byte[] counterBytes = new byte[4];
            BigEndianConversions.I2OSP(counter, counterBytes, 0);

            // Step b: Concatenate hash of seed and counterBytes with intermediate result
            ByteBuffer digestInputBuffer = ByteBuffer.allocate(seed.length + 4);
            digestInputBuffer.put(seed);
            digestInputBuffer.put(counterBytes);
            ByteBuffer digestOutput = ByteBuffer.wrap(digest.digest(digestInputBuffer.array()));
            result.put(digestOutput);
        }

        // Result are first maskLen bytes
        return Arrays.copyOfRange(result.array(), 0, maskLen);
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
