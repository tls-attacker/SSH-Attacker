/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Scanner;
import java.util.stream.Stream;
import javax.xml.bind.DatatypeConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class JavaCipherTest {

    private static final Logger LOGGER = LogManager.getLogger();

    public static String[] aesCbcTestVectorFileNames = {
        "CBCGFSbox128.rsp",
        "CBCGFSbox192.rsp",
        "CBCGFSbox256.rsp",
        "CBCKeySbox128.rsp",
        "CBCKeySbox192.rsp",
        "CBCKeySbox256.rsp",
        "CBCVarKey128.rsp",
        "CBCVarKey192.rsp",
        "CBCVarKey256.rsp",
        "CBCVarTxt128.rsp",
        "CBCVarTxt192.rsp",
        "CBCVarTxt256.rsp"
    };

    public static String[] aesEncryptionGcmTestVectorFileNames = {
        "gcmEncryptExtIV128.rsp", "gcmEncryptExtIV256.rsp"
    };

    public static String[] aesDecryptionGcmTestVectorFileNames = {
        "gcmDecrypt128.rsp", "gcmDecrypt256.rsp"
    };

    public static Stream<Arguments> provideArcFourTestVectors() {
        InputStream testVectorFile =
                JavaCipherTest.class.getClassLoader().getResourceAsStream("arcfour.txt");
        assert testVectorFile != null;
        Scanner reader = new Scanner(testVectorFile);
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
        String line;
        EncryptionAlgorithm encryptionAlgorithm = null;
        while (reader.hasNextLine()) {
            line = reader.nextLine();
            if (line.startsWith("[128 Bit]")) {
                encryptionAlgorithm = EncryptionAlgorithm.ARCFOUR128;
            }
            if (line.startsWith("[256 Bit]")) {
                encryptionAlgorithm = EncryptionAlgorithm.ARCFOUR256;
            }
            if (line.startsWith("COUNT")) {
                line = reader.nextLine();
                byte[] key = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] plaintext = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] ciphertext = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                argumentsBuilder.add(Arguments.of(encryptionAlgorithm, key, plaintext, ciphertext));
            }
        }
        return argumentsBuilder.build();
    }

    public static Stream<Arguments> provideAesTestVectors() {
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();

        InputStream testVectorFile;
        Scanner reader;
        String line;
        EncryptionAlgorithm encryptionAlgorithm = null;
        for (String testVectorName : aesCbcTestVectorFileNames) {
            testVectorFile =
                    JavaCipherTest.class
                            .getClassLoader()
                            .getResourceAsStream("./AESAVS/" + testVectorName);
            assert testVectorFile != null;
            reader = new Scanner(testVectorFile);
            char testingMode = 'e';
            while (reader.hasNextLine()) {
                line = reader.nextLine();
                if (line.startsWith("[DECRYPT]")) {
                    testingMode = 'd';
                }

                if (line.startsWith("# Key Length : ")) {
                    String keyLength = line.split(" : ")[1];
                    switch (keyLength) {
                        case "128":
                            encryptionAlgorithm = EncryptionAlgorithm.AES128_CBC;
                            break;
                        case "192":
                            encryptionAlgorithm = EncryptionAlgorithm.AES192_CBC;
                            break;
                        case "256":
                            encryptionAlgorithm = EncryptionAlgorithm.AES256_CBC;
                            break;
                    }
                }

                if (line.startsWith("COUNT")) {
                    line = reader.nextLine();
                    byte[] key = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();
                    byte[] iv = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();
                    byte[] plaintext;
                    byte[] ciphertext;
                    if (testingMode == 'e') {
                        plaintext = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                        line = reader.nextLine();
                        ciphertext = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    } else {
                        ciphertext = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                        line = reader.nextLine();
                        plaintext = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    }
                    argumentsBuilder.add(
                            Arguments.of(
                                    encryptionAlgorithm,
                                    testingMode,
                                    key,
                                    iv,
                                    plaintext,
                                    ciphertext));
                }
            }
        }
        return argumentsBuilder.build();
    }

    public static Stream<Arguments> provideGcmTestVectors(String[] aesGcmTestVectorFileNames) {
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();

        InputStream testVectorFile;
        Scanner reader;
        String line;
        EncryptionAlgorithm encryptionAlgorithm = null;
        for (String testVectorName : aesGcmTestVectorFileNames) {
            testVectorFile =
                    JavaCipherTest.class
                            .getClassLoader()
                            .getResourceAsStream("./GCMVS/" + testVectorName);
            assert testVectorFile != null;
            reader = new Scanner(testVectorFile);

            while (reader.hasNextLine()) {
                line = reader.nextLine();

                if (line.startsWith("[Keylen =")) {
                    String keyLength = line.split(" = ")[1].replace("]", "");
                    switch (keyLength) {
                        case "128":
                            encryptionAlgorithm = EncryptionAlgorithm.AEAD_AES_128_GCM;
                            break;
                        case "256":
                            encryptionAlgorithm = EncryptionAlgorithm.AEAD_AES_256_GCM;
                            break;
                    }
                }

                if (line.startsWith("Count")) {
                    line = reader.nextLine();
                    byte[] key = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();
                    byte[] iv = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();

                    byte[] plaintext = new byte[0];
                    byte[] aad = new byte[0];
                    byte[] ciphertext = new byte[0];
                    byte[] tag = new byte[0];
                    boolean decryptable = true;
                    if (testVectorName.contains("Encrypt")) {
                        String[] splittedLine = line.split(" = ");
                        if (splittedLine.length > 1) {
                            plaintext = DatatypeConverter.parseHexBinary(splittedLine[1]);
                        }
                        line = reader.nextLine();
                        splittedLine = line.split(" = ");
                        if (splittedLine.length > 1) {
                            aad = DatatypeConverter.parseHexBinary(splittedLine[1]);
                        }
                        line = reader.nextLine();
                        splittedLine = line.split(" = ");
                        if (splittedLine.length > 1) {
                            ciphertext = DatatypeConverter.parseHexBinary(splittedLine[1]);
                        }
                        line = reader.nextLine();
                        splittedLine = line.split(" = ");
                        if (splittedLine.length > 1) {
                            tag = DatatypeConverter.parseHexBinary(splittedLine[1]);
                        }
                        argumentsBuilder.add(
                                Arguments.of(
                                        encryptionAlgorithm,
                                        key,
                                        iv,
                                        plaintext,
                                        aad,
                                        ciphertext,
                                        tag));
                    } else {
                        String[] splittedLine = line.split(" = ");
                        if (splittedLine.length > 1) {
                            ciphertext = DatatypeConverter.parseHexBinary(splittedLine[1]);
                        }
                        line = reader.nextLine();
                        splittedLine = line.split(" = ");
                        if (splittedLine.length > 1) {
                            aad = DatatypeConverter.parseHexBinary(splittedLine[1]);
                        }
                        line = reader.nextLine();
                        splittedLine = line.split(" = ");
                        if (splittedLine.length > 1) {
                            tag = DatatypeConverter.parseHexBinary(splittedLine[1]);
                        }
                        line = reader.nextLine();
                        splittedLine = line.split(" = ");
                        if (line.startsWith("FAIL")) {
                            decryptable = false;
                        } else if (splittedLine.length > 1) {
                            plaintext = DatatypeConverter.parseHexBinary(splittedLine[1]);
                        }
                        argumentsBuilder.add(
                                Arguments.of(
                                        encryptionAlgorithm,
                                        key,
                                        iv,
                                        plaintext,
                                        aad,
                                        ciphertext,
                                        tag,
                                        decryptable));
                    }
                }
            }
        }
        return argumentsBuilder.build();
    }

    public static Stream<Arguments> provideGcmTestVectorsDecryption() {
        return provideGcmTestVectors(aesDecryptionGcmTestVectorFileNames);
    }

    public static Stream<Arguments> provideGcmTestVectorsEncryption() {
        return provideGcmTestVectors(aesEncryptionGcmTestVectorFileNames);
    }

    /**
     * Tests the encryption of JavaCipher using a stream cipher, at the moment arcfour128 and
     * arcfour256 test vectors are provided for testing.
     *
     * @param encryptionAlgorithm encryption algorithm to use
     * @param key the used private key
     * @param plaintext plaintext to be encrypted
     * @param ciphertext expected ciphertext
     */
    @ParameterizedTest(name = "Algorithm:{0}, Key: {1}")
    @MethodSource("provideArcFourTestVectors")
    void testEncryptionStreamCipher(
            EncryptionAlgorithm encryptionAlgorithm,
            byte[] key,
            byte[] plaintext,
            byte[] ciphertext) {
        int keyLength = key.length;
        LOGGER.debug(encryptionAlgorithm.toString());
        LOGGER.debug("Key length in bytes: " + keyLength);
        JavaCipher cipher = new JavaCipher(encryptionAlgorithm, key, true);
        assertEquals(cipher.getAlgorithm(), encryptionAlgorithm);
        try {
            byte[] encText = cipher.encrypt(plaintext);
            LOGGER.debug("Expected ciphertext: " + DatatypeConverter.printHexBinary(ciphertext));
            LOGGER.debug("Computed ciphertext: " + DatatypeConverter.printHexBinary(encText));
            assertArrayEquals(ciphertext, encText);
        } catch (CryptoException e) {
            LOGGER.error(e);
        }
    }

    /**
     * Tests the decryption of JavaCipher using a stream cipher, at the moment arcfour128 and
     * arcfour256 test vectors are provided for testing.
     *
     * @param encryptionAlgorithm encryption algorithm to use
     * @param key the used private key
     * @param plaintext the expected plaintext
     * @param ciphertext the ciphertext to be decrypted
     */
    @ParameterizedTest(name = "Algorithm:{0}, Key: {1}")
    @MethodSource("provideArcFourTestVectors")
    void testDecryptionStreamCipher(
            EncryptionAlgorithm encryptionAlgorithm,
            byte[] key,
            byte[] plaintext,
            byte[] ciphertext) {
        int keyLength = key.length;
        LOGGER.debug("Key length in bytes: " + keyLength);
        JavaCipher cipher = new JavaCipher(encryptionAlgorithm, key, true);
        assertEquals(cipher.getAlgorithm(), encryptionAlgorithm);
        try {
            byte[] decText = cipher.decrypt(ciphertext);
            LOGGER.debug("Expected plaintext: " + DatatypeConverter.printHexBinary(plaintext));
            LOGGER.debug("Computed plaintext: " + DatatypeConverter.printHexBinary(decText));
            assertArrayEquals(plaintext, decText);
        } catch (CryptoException e) {
            LOGGER.error(e);
        }
    }

    /**
     * Tests the encyption and decryption of JavaCipher using a block cipher, at the moment
     * aes128-cbc, aes192-cbc and aes256-cbc is used for testing. The testing mode switches, whether
     * to test the encryption or the decryption of the block cipher.
     *
     * @param encryptionAlgorithm encryption algorithm to use
     * @param testingMode specifies if encryption[e] or decryption[d] shpould be tested
     * @param key used private key
     * @param iv used initial vector
     * @param plaintext provided[e] or expected[d] plaintext
     * @param ciphertext provided[d] or expected[e] ciphertext
     */
    @ParameterizedTest(name = "Algorithm: {0}, TestingMode: {1}, Key: {2}")
    @MethodSource("provideAesTestVectors")
    void testEncryption_DecryptionBlockCipher(
            EncryptionAlgorithm encryptionAlgorithm,
            char testingMode,
            byte[] key,
            byte[] iv,
            byte[] plaintext,
            byte[] ciphertext) {
        int keyLength = key.length;
        LOGGER.debug("Key length in bytes: " + keyLength);
        JavaCipher cipher = new JavaCipher(encryptionAlgorithm, key, true);
        assertEquals(cipher.getAlgorithm(), encryptionAlgorithm);
        switch (testingMode) {
            case 'e':
                try {
                    byte[] encText = cipher.encrypt(plaintext, iv);
                    LOGGER.debug(
                            "Expected ciphertext: " + DatatypeConverter.printHexBinary(ciphertext));
                    LOGGER.debug(
                            "Computed ciphertext: " + DatatypeConverter.printHexBinary(encText));
                    assertArrayEquals(ciphertext, encText);
                } catch (CryptoException e) {
                    LOGGER.error(e);
                }
                break;
            case 'd':
                try {
                    byte[] decText = cipher.decrypt(ciphertext, iv);
                    LOGGER.debug(
                            "Expected plaintext: " + DatatypeConverter.printHexBinary(plaintext));
                    LOGGER.debug(
                            "Computed plaintext: " + DatatypeConverter.printHexBinary(decText));
                    assertArrayEquals(plaintext, decText);
                } catch (CryptoException e) {
                    LOGGER.error(e);
                }
                break;
        }
    }

    /**
     * Tests the encryption of JavaCipher using a aead cipher, at the moment AEAD_AES_128_GCM and
     * AEAD_AES_256_GCM are tested.
     *
     * @param encryptionAlgorithm encryption algorithm to use
     * @param key used private key
     * @param iv used initial vector
     * @param plaintext plaintext to be encrypted
     * @param aad provided additional authenticated data
     * @param ciphertext expected ciphertext
     * @param tag expected generated tag
     */
    @ParameterizedTest(name = "Algorithm:{0}, Key: {1}")
    @MethodSource("provideGcmTestVectorsEncryption")
    void testEncryptionAeadCipher(
            EncryptionAlgorithm encryptionAlgorithm,
            byte[] key,
            byte[] iv,
            byte[] plaintext,
            byte[] aad,
            byte[] ciphertext,
            byte[] tag) {
        int keyLength = key.length;
        LOGGER.debug("Key length in bytes: " + keyLength);
        JavaCipher cipher = new JavaCipher(encryptionAlgorithm, key, true);
        assertEquals(cipher.getAlgorithm(), encryptionAlgorithm);
        try {
            byte[] fullEncText = cipher.encrypt(plaintext, iv, aad);
            LOGGER.debug("Expected tag: " + DatatypeConverter.printHexBinary(tag));
            LOGGER.debug("Expected ciphertext: " + DatatypeConverter.printHexBinary(ciphertext));

            byte[] computedCiphertext = Arrays.copyOfRange(fullEncText, 0, fullEncText.length - 16);
            byte[] computedTag =
                    Arrays.copyOfRange(fullEncText, fullEncText.length - 16, fullEncText.length);
            LOGGER.debug("Computed tag: " + DatatypeConverter.printHexBinary(computedTag));
            LOGGER.debug("Computed ciphertext: " + DatatypeConverter.printHexBinary(fullEncText));
            assertArrayEquals(tag, computedTag);
            assertArrayEquals(ciphertext, computedCiphertext);
        } catch (CryptoException e) {
            LOGGER.error(e);
        }
    }

    /**
     * Tests the encryption of JavaCipher using a aead cipher, at the moment AEAD_AES_128_GCM and
     * AEAD_AES_256_GCM are tested.
     *
     * @param encryptionAlgorithm encryption algorithm to use
     * @param key used private key
     * @param iv used initial vector
     * @param plaintext expected plaintext
     * @param aad provided additional authenticated data
     * @param ciphertext ciphertext to be decrypted
     * @param tag provided authentication tag
     * @param decryptable specifies if tag belongs to the ciphertext and thus ciphertext is
     *     decryptable
     */
    @ParameterizedTest(name = "Algorithm:{0}, Key: {1}")
    @MethodSource("provideGcmTestVectorsDecryption")
    void testDecryptionAeadCipher(
            EncryptionAlgorithm encryptionAlgorithm,
            byte[] key,
            byte[] iv,
            byte[] plaintext,
            byte[] aad,
            byte[] ciphertext,
            byte[] tag,
            boolean decryptable) {
        int keyLength = key.length;
        LOGGER.debug("Key length in bytes: " + keyLength);
        JavaCipher cipher = new JavaCipher(encryptionAlgorithm, key, true);
        assertEquals(cipher.getAlgorithm(), encryptionAlgorithm);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ciphertext);
            outputStream.write(tag);
        } catch (IOException e) {
            LOGGER.debug(e);
        }
        byte[] fullCiphertext = outputStream.toByteArray();

        try {
            LOGGER.debug("Expected ciphertext: " + DatatypeConverter.printHexBinary(ciphertext));
            byte[] decText = cipher.decrypt(fullCiphertext, iv, aad);
            LOGGER.debug("Expected tag: " + DatatypeConverter.printHexBinary(fullCiphertext));
            assertArrayEquals(plaintext, decText);
        } catch (CryptoException e) {
            if (!decryptable) {
                LOGGER.debug("CryptoException was thrown right: " + e.getCause().toString());
            } else {
                LOGGER.error(e);
            }
        }
    }
}
