/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.sshattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.Bits;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

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
     * @param  publicKey
     * @return
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
        byte[] keyBytes = new byte[publicKeyBitLength - 2 * hashLength - 49];
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
     * @param  symmetricKey
     *                      symmetric key to be padded
     * @return              padded key
     */
    private static byte[] getPaddedKey(int rsaKeyLength, byte[] symmetricKey) {
        //TODO: generate correct message
        byte[] key = new byte[rsaKeyLength];
        // fill all the bytes with non-zero values
        Arrays.fill(key, (byte) 42);
        // set the first byte to 0x00
        key[0] = 0x00;
        // set the second byte to 0x02
        key[1] = 0x02;
        // set the separating byte
        key[rsaKeyLength - symmetricKey.length - 1] = 0x00;
        // copy the symmetric key to the field
        System.arraycopy(symmetricKey, 0, key, rsaKeyLength - symmetricKey.length, symmetricKey.length);
        LOGGER.debug("Generated a PKCS1 padded message a correct key length, but invalid protocol version: {}",
            ArrayConverter.bytesToHexString(key));

        return key;
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
}
