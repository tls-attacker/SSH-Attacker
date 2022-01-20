/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.mac;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Implemention of the UMAC message authentication code as per RFC4418. This implementation is
 * restricted to inputs consisting out of full bytes only and of length less or equal to 2^24 bytes
 * (16 MB).
 */
class UMac implements WrappedMac {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final BigInteger INT_MOD = BigInteger.ONE.shiftLeft(32);
    private static final BigInteger LONG_MOD = BigInteger.ONE.shiftLeft(64);
    private static final int BLOCKLEN = 16;
    private static final int KEYLEN = 16;

    private final MacAlgorithm algorithm;
    private final byte[] key;

    public UMac(MacAlgorithm algorithm, byte[] key) {
        if (!algorithm.toString().startsWith("umac")) {
            throw new UnsupportedOperationException(
                    "MAC algorithm not supported by UMAC implementation: " + algorithm);
        }
        this.algorithm = algorithm;
        this.key = key;
    }

    @Override
    public byte[] calculate(int sequenceNumber, byte[] unencryptedPacket) {
        return UMAC(
                key,
                unencryptedPacket,
                ArrayConverter.intToBytes(sequenceNumber, DataFormatConstants.INT64_SIZE),
                algorithm.getOutputSize());
    }

    @Override
    public MacAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * UMAC-32 Algorithm (RFC 4418 Section 4.2)
     *
     * @param K String of length KEYLEN bytes.
     * @param M String of length less than 2^67 bits (this implementation enforces M to be a string
     *     of bytes).
     * @param Nonce String of length 1 to BLOCKLEN bytes.
     */
    public static byte[] UMAC32(byte[] K, byte[] M, byte[] Nonce) {
        return UMAC(K, M, Nonce, 4);
    }

    /**
     * UMAC-32 Algorithm (RFC 4418 Section 4.2)
     *
     * @param K String of length KEYLEN bytes.
     * @param M String of length less than 2^67 bits (this implementation enforces M to be a string
     *     of bytes).
     * @param Nonce String of length 1 to BLOCKLEN bytes.
     */
    public static byte[] UMAC64(byte[] K, byte[] M, byte[] Nonce) {
        return UMAC(K, M, Nonce, 8);
    }

    /**
     * UMAC-32 Algorithm (RFC 4418 Section 4.2)
     *
     * @param K String of length KEYLEN bytes.
     * @param M String of length less than 2^67 bits (this implementation enforces M to be a string
     *     of bytes).
     * @param Nonce String of length 1 to BLOCKLEN bytes.
     */
    public static byte[] UMAC96(byte[] K, byte[] M, byte[] Nonce) {
        return UMAC(K, M, Nonce, 12);
    }

    /**
     * UMAC-32 Algorithm (RFC 4418 Section 4.2)
     *
     * @param K String of length KEYLEN bytes.
     * @param M String of length less than 2^67 bits (this implementation enforces M to be a string
     *     of bytes).
     * @param Nonce String of length 1 to BLOCKLEN bytes.
     */
    public static byte[] UMAC128(byte[] K, byte[] M, byte[] Nonce) {
        return UMAC(K, M, Nonce, 16);
    }

    /**
     * UMAC Algorithm (RFC 4418 Section 4.1)
     *
     * @param K String of length KEYLEN bytes.
     * @param M String of length less than 2^67 bits (this implementation enforces M to be a string
     *     of bytes).
     * @param Nonce String of length 1 to BLOCKLEN bytes.
     * @param taglen The integer 4, 8, 12 or 16.
     */
    public static byte[] UMAC(byte[] K, byte[] M, byte[] Nonce, int taglen) {
        byte[] HashedMessage = UHASH(K, M, taglen);
        byte[] Pad = PDF(K, Nonce, taglen);
        byte[] Tag = new byte[taglen];
        for (int i = 0; i < taglen; i++) {
            Tag[i] = (byte) (HashedMessage[i] ^ Pad[i]);
        }
        return Tag;
    }

    /**
     * UHASH Algorithm (RFC 4418 Section 5.1)
     *
     * @param K String of length KEYLEN bytes.
     * @param M String of length less than 2^67 bits (this implementation enforces M to be a string
     *     of bytes).
     * @param taglen The integer 4, 8, 12 or 16.
     * @return The hash value under UHASH keyed with K and input M.
     */
    public static byte[] UHASH(byte[] K, byte[] M, int taglen) {
        int iters = taglen / 4;

        byte[] L1Key = KDF(K, 1, 1024 + (iters - 1) * 16);
        byte[] L2Key = KDF(K, 2, iters * 24);
        byte[] L3Key1 = KDF(K, 3, iters * 64);
        byte[] L3Key2 = KDF(K, 4, iters * 4);

        byte[] Y = new byte[0];
        for (int i = 0; i < iters; i++) {
            byte[] L1Key_i = Arrays.copyOfRange(L1Key, i * 16, i * 16 + 1024);
            byte[] L2Key_i = Arrays.copyOfRange(L2Key, i * 24, (i + 1) * 24);
            byte[] L3Key1_i = Arrays.copyOfRange(L3Key1, i * 64, (i + 1) * 64);
            byte[] L3Key2_i = Arrays.copyOfRange(L3Key2, i * 4, (i + 1) * 4);

            byte[] A = L1_HASH(L1Key_i, M);
            byte[] B;
            if (bitlength(M) <= bitlength(L1Key_i)) {
                B = ArrayConverter.concatenate(new byte[8], A);
            } else {
                B = L2_HASH(L2Key_i, A);
            }
            byte[] C = L3_HASH(L3Key1_i, L3Key2_i, B);
            Y = ArrayConverter.concatenate(Y, C);
        }
        return Y;
    }

    /**
     * KDF Algorithm (RFC 4418 Section 3.2.1)
     *
     * @param K String of length KEYLEN bytes.
     * @param index A non-negative integer less than 2^64 (only less than 2^31 is implemented).
     * @param numbytes A non-negative integer less than 2^64 (only less than 2^31 is implemented).
     */
    static byte[] KDF(byte[] K, int index, int numbytes) {
        int n = (int) Math.ceil(numbytes / (double) BLOCKLEN);
        byte[] Y = new byte[0];
        for (int i = 0; i < n; i++) {
            byte[] T =
                    ArrayConverter.concatenate(
                            ArrayConverter.intToBytes(index, BLOCKLEN - 8),
                            ArrayConverter.intToBytes(i + 1, 8));
            T = ENCIPHER(K, T);
            assert T != null;
            Y = ArrayConverter.concatenate(Y, T);
        }
        Y = Arrays.copyOfRange(Y, 0, numbytes);
        return Y;
    }

    /**
     * PDF Algorithm (RFC 4418 Section 3.3.1)
     *
     * @param K String of length KEYLEN bytes.
     * @param Nonce String of length 1 to BLOCKLEN bytes.
     * @param taglen The integer 4, 8, 12 or 16.
     * @return Y, string of length taglen bytes.
     */
    static byte[] PDF(byte[] K, byte[] Nonce, int taglen) {
        int index = 0;
        // Clone Nonce array to avoid modifications to the original nonce array
        Nonce = Nonce.clone();
        if (taglen == 4 || taglen == 8) {
            index =
                    new BigInteger(1, Nonce)
                            .mod(BigInteger.valueOf(BLOCKLEN / taglen))
                            .intValueExact();
            byte[] indexBytes = ArrayConverter.intToBytes(index, Nonce.length);
            for (int i = 0; i < Nonce.length; i++) {
                Nonce[i] = (byte) (Nonce[i] ^ indexBytes[i]);
            }
        }
        Nonce = ArrayConverter.concatenate(Nonce, new byte[BLOCKLEN - Nonce.length]);
        byte[] KPrime = KDF(K, 0, KEYLEN);
        byte[] T = ENCIPHER(KPrime, Nonce);
        assert T != null;
        return Arrays.copyOfRange(T, index * taglen, taglen + (index * taglen));
    }

    /**
     * ENDIAN-SWAP Algorithm (RFC 4418 Section 2.5.1)
     *
     * @param s String with length divisible by 4 bytes.
     * @return String s with each 4-byte word endian-reversed.
     */
    static byte[] ENDIAN_SWAP(byte[] s) {
        byte[] t = new byte[s.length];
        for (int i = 0; i < s.length; i += 4) {
            for (int j = 0; j < 4; j++) {
                t[i + j] = s[i + (3 - j)];
            }
        }
        return t;
    }

    /**
     * L1-HASH Algorithm (RFC 4418 Section 5.2.1)
     *
     * @param K String of length 1024 bytes.
     * @param M String of length less than 2^67 bits (bytes only, single bits are not supported).
     * @return Y, string of length (8 * ceil(bitlength(m)/8192)) bytes.
     */
    static byte[] L1_HASH(byte[] K, byte[] M) {
        int t = Math.max((int) Math.ceil(bitlength(M) / 8192.0), 1);
        byte[][] M_ = new byte[t][];
        for (int i = 0; i < t; i++) {
            int chunkStart = 1024 * i;
            int chunkEnd = Math.min(chunkStart + 1024, M.length);
            M_[i] = Arrays.copyOfRange(M, chunkStart, chunkEnd);
        }
        byte[] Len = ArrayConverter.intToBytes(1024 * Byte.SIZE, 8);
        byte[] Y = new byte[0];
        for (int i = 0; i < t - 1; i++) {
            M_[i] = ENDIAN_SWAP(M_[i]);
            Y = ArrayConverter.concatenate(Y, add64(NH(K, M_[i]), Len));
        }
        Len = ArrayConverter.intToBytes(bitlength(M_[t - 1]), 8);
        M_[t - 1] = zeropad(M_[t - 1], 32);
        M_[t - 1] = ENDIAN_SWAP(M_[t - 1]);
        Y = ArrayConverter.concatenate(Y, add64(NH(K, M_[t - 1]), Len));
        return Y;
    }

    /**
     * NH Algorithm (RFC 4418 Section 5.2.2)
     *
     * @param K String of length 1024 bytes.
     * @param M String with length divisible by 32 bytes.
     * @return Y, string of length 8 bytes.
     */
    static byte[] NH(byte[] K, byte[] M) {
        int t = M.length / 4;
        byte[][] M_ = new byte[t][];
        byte[][] K_ = new byte[t][];
        for (int i = 0; i < t; i++) {
            M_[i] = Arrays.copyOfRange(M, 4 * i, 4 * (i + 1));
            K_[i] = Arrays.copyOfRange(K, 4 * i, 4 * (i + 1));
        }
        byte[] Y = new byte[8];
        int i = 0;
        while (i < t - 1) {
            Y = add64(Y, mult64(add32(M_[i], K_[i]), add32(M_[i + 4], K_[i + 4])));
            Y = add64(Y, mult64(add32(M_[i + 1], K_[i + 1]), add32(M_[i + 5], K_[i + 5])));
            Y = add64(Y, mult64(add32(M_[i + 2], K_[i + 2]), add32(M_[i + 6], K_[i + 6])));
            Y = add64(Y, mult64(add32(M_[i + 3], K_[i + 3]), add32(M_[i + 7], K_[i + 7])));
            i += 8;
        }
        return Y;
    }

    /**
     * L2-HASH Algorithm (RFC 4418 Section 5.3.1)
     *
     * @param K String of length 24 bytes.
     * @param M String of length less than 2^64 bytes.
     * @return Y, string of length 16 bytes.
     */
    static byte[] L2_HASH(byte[] K, byte[] M) {
        byte[] Mask64 = ArrayConverter.hexStringToByteArray("01ffffff01ffffff");
        byte[] k64Bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            k64Bytes[i] = (byte) (K[i] & Mask64[i]);
        }
        BigInteger k64 = new BigInteger(1, k64Bytes);
        BigInteger y;
        if (M.length <= (1 << 17)) {
            y =
                    POLY(
                            64,
                            BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE.shiftLeft(32)),
                            k64,
                            M);
        } else {
            throw new NotImplementedException(
                    "This UMAC implementation does not support inputs larger than 2^24 bytes (16 MB)");
        }
        return ArrayConverter.bigIntegerToNullPaddedByteArray(y, 16);
    }

    /**
     * POLY Algorithm (RFC 4418 Section 5.3.2)
     *
     * @param wordbits The integer 64 or 128.
     * @param maxwordrange Positive integer less than 2^wordbits.
     * @param k Integer in the range 0 ... prime(wordbits) - 1.
     * @param M String with length divisible by (wordbits / 8) bytes.
     * @return y, integer in the range 0 ... prime(wordbits) - 1.
     */
    static BigInteger POLY(int wordbits, BigInteger maxwordrange, BigInteger k, byte[] M) {
        int wordbytes = wordbits / Byte.SIZE;
        BigInteger p = prime(wordbits);
        BigInteger offset = BigInteger.ONE.shiftLeft(wordbits).subtract(p);
        BigInteger marker = p.subtract(BigInteger.ONE);
        int n = M.length / wordbytes;
        byte[][] M_ = new byte[n][];
        for (int i = 0; i < n; i++) {
            M_[i] = Arrays.copyOfRange(M, i * wordbytes, (i + 1) * wordbytes);
        }
        BigInteger y = BigInteger.ONE;
        for (int i = 0; i < n; i++) {
            BigInteger m = new BigInteger(1, M_[i]);
            if (m.compareTo(maxwordrange) >= 0) {
                y = y.multiply(k).add(marker).mod(p);
                y = y.multiply(k).add(m.subtract(offset)).mod(p);
            } else {
                y = y.multiply(k).add(m).mod(p);
            }
        }
        return y;
    }

    /**
     * L3-HASH Algorithm (RFC 4418 Section 5.4.1)
     *
     * @param K1 String of length 64 bytes.
     * @param K2 String of length 4 bytes.
     * @param M String of length 16 bytes.
     * @return Y, string of length 4 bytes.
     */
    static byte[] L3_HASH(byte[] K1, byte[] K2, byte[] M) {
        BigInteger y = BigInteger.ZERO;
        byte[][] M_ = new byte[8][];
        byte[][] K_ = new byte[8][];
        BigInteger[] m_ = new BigInteger[8];
        BigInteger[] k_ = new BigInteger[8];
        for (int i = 0; i < 8; i++) {
            M_[i] = Arrays.copyOfRange(M, 2 * i, 2 * (i + 1));
            K_[i] = Arrays.copyOfRange(K1, 8 * i, 8 * (i + 1));
            m_[i] = new BigInteger(1, M_[i]);
            k_[i] = new BigInteger(1, K_[i]).mod(prime(36));
        }
        for (int i = 0; i < 8; i++) {
            y = y.add(m_[i].multiply(k_[i]));
        }
        y = y.mod(prime(36)).mod(BigInteger.ONE.shiftLeft(32));
        byte[] Y = ArrayConverter.bigIntegerToByteArray(y);
        for (int i = 0; i < 4; i++) {
            Y[i] = (byte) (Y[i] ^ K2[i]);
        }
        return Y;
    }

    /**
     * Simple ECB encryption using AES.
     *
     * @param K AES cipher key.
     * @param P Plaintext bytes to encrypt.
     * @return The ciphertext enc_K(P).
     */
    static byte[] ENCIPHER(byte[] K, byte[] P) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(K, "AES"));
            return cipher.doFinal(P);
        } catch (IllegalBlockSizeException
                | BadPaddingException
                | NoSuchPaddingException
                | NoSuchAlgorithmException
                | InvalidKeyException e) {
            LOGGER.error(e);
            return null;
        }
    }

    /**
     * Returns the largest prime number less than 2^n (implemented for n = 36, 64, and 128 only)
     *
     * @param n Upper bound for prime number (only n = 36, 64, and 128 are supported)
     * @return The largest prime number less than 2^n.
     */
    static BigInteger prime(int n) {
        switch (n) {
            case 36:
                return BigInteger.ONE.shiftLeft(36).subtract(BigInteger.valueOf(5));
            case 64:
                return BigInteger.ONE.shiftLeft(64).subtract(BigInteger.valueOf(59));
            case 128:
                return BigInteger.ONE.shiftLeft(128).subtract(BigInteger.valueOf(159));
            default:
                throw new NotImplementedException(
                        "prime() for value n = " + n + " is not implemented.");
        }
    }

    static byte[] add32(byte[] a, byte[] b) {
        return ArrayConverter.bigIntegerToNullPaddedByteArray(
                new BigInteger(1, a).add(new BigInteger(1, b)).mod(INT_MOD), 4);
    }

    static byte[] add64(byte[] a, byte[] b) {
        return ArrayConverter.bigIntegerToNullPaddedByteArray(
                new BigInteger(1, a).add(new BigInteger(1, b).mod(LONG_MOD)), 8);
    }

    static byte[] mult64(byte[] a, byte[] b) {
        return ArrayConverter.bigIntegerToNullPaddedByteArray(
                new BigInteger(1, a).multiply(new BigInteger(1, b).mod(LONG_MOD)), 8);
    }

    /**
     * Pads a byte array to a multiple of the specified length (in bytes) by appending zeroes to the
     * right.
     *
     * @param a Byte array to pad
     * @param byteBoundary Byte boundary to pad to.
     * @return The padded byte array.
     */
    static byte[] zeropad(byte[] a, int byteBoundary) {
        int paddingLength =
                a.length == 0
                        ? byteBoundary
                        : (byteBoundary - a.length % byteBoundary) % byteBoundary;
        return ArrayConverter.concatenate(a, new byte[paddingLength]);
    }

    static int bitlength(byte[] a) {
        return Byte.SIZE * a.length;
    }
}
