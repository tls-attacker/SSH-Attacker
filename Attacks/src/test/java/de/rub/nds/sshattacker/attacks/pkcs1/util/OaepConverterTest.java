/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1.util;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;

import static org.junit.jupiter.api.Assertions.*;

public class OaepConverterTest {

    @Test
    public void xorTest() {
        byte[] leftInput = new byte[2];
        leftInput[0] = (byte) 17;
        leftInput[1] = (byte) 1;
        byte[] rightInput = new byte[2];
        rightInput[0] = (byte) 22;
        rightInput[1] = (byte) 42;
        byte[] expectedOutput = new byte[2];
        expectedOutput[0] = (byte) 7;
        expectedOutput[1] = (byte) 43;

        assertArrayEquals(expectedOutput, OaepConverter.xor(leftInput, rightInput));
    }

    @Test
    public void mgf1Test() {
        String input = "bar";
        String output =
                "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1";
        try {
            byte[] maskBytes =
                    OaepConverter.mgf1(input.getBytes(StandardCharsets.UTF_8), 50, "SHA-256");
            String maskedBytesInHex = new BigInteger(maskBytes).toString(16);
            assertEquals(output, maskedBytesInHex);
        } catch (NoSuchAlgorithmException e) {
            fail("Test failed because hash alg does not exist.");
        }
    }

    @Test
    public void oaepTest() {
        byte[] message = new byte[1];
        message[0] = (byte) 42;
        try {
            byte[] bytes = OaepConverter.doOaepEncoding(message, "SHA-256", 256);
            byte[] result = OaepConverter.doOaepDecoding(bytes, "SHA-256", 256);
            assertArrayEquals(message, result);
        } catch (NoSuchAlgorithmException e) {
            fail("Test failed because hash alg does not exist.");
        }
    }

    @Test
    public void encryptionTest() {
        byte[] message = new byte[1];
        message[0] = (byte) 42;

        try {
            // Generate RSA key pair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            // Encode and perform raw encryption
            Security.addProvider(new BouncyCastleProvider());
            byte[] encodedMessage = OaepConverter.doOaepEncoding(message, "SHA-256", 256);
            Cipher rawCipher = Cipher.getInstance("RSA/NONE/NoPadding");
            rawCipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            byte[] encryptedMessage = rawCipher.doFinal(encodedMessage);

            // Do decryption using OAEP Cipher
            DecryptionCipher oaepCipher =
                    CipherFactory.getDecryptionCipher(
                            KeyExchangeAlgorithm.RSA2048_SHA256, kp.getPrivate());
            byte[] result = oaepCipher.decrypt(encryptedMessage);

            assertArrayEquals(message, result);
        } catch (NoSuchPaddingException
                | NoSuchAlgorithmException
                | InvalidKeyException
                | IllegalBlockSizeException
                | BadPaddingException
                | CryptoException e) {
            fail("Test failed because an error occurred: " + e.getMessage());
        }
    }

    @Test
    public void decryptionTest() {
        byte[] message = new byte[1];
        message[0] = (byte) 42;

        try {
            // Generate RSA key pair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            // Do encryption using OAEP Cipher
            EncryptionCipher oaepCipher =
                    CipherFactory.getEncryptionCipher(
                            KeyExchangeAlgorithm.RSA2048_SHA256, kp.getPublic());
            byte[] encryptedMessage = oaepCipher.encrypt(message);

            // Do raw decrypt
            Security.addProvider(new BouncyCastleProvider());
            Cipher rawCipher = Cipher.getInstance("RSA/NONE/NoPadding");
            rawCipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            byte[] encodedMessage = rawCipher.doFinal(encryptedMessage);

            // Add a 00 byte in the beginning, as the raw RSA cipher will ignore this and return a
            // 255 byte array,
            // if the decryption works correctly, which it should as none of the tested classes are
            // used up to now
            ByteBuffer buffer = ByteBuffer.allocate(256);
            buffer.put((byte) 0);
            buffer.put(encodedMessage);

            // Perform the decoding
            byte[] result = OaepConverter.doOaepDecoding(buffer.array(), "SHA-256", 256);

            assertArrayEquals(message, result);
        } catch (NoSuchPaddingException
                | NoSuchAlgorithmException
                | InvalidKeyException
                | IllegalBlockSizeException
                | BadPaddingException
                | CryptoException e) {
            fail("Test failed because an error occurred: " + e.getMessage());
        }
    }
}
