/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.io.InputStream;
import java.security.Security;
import java.util.Arrays;
import java.util.Scanner;
import java.util.stream.Stream;
import javax.crypto.AEADBadTagException;
import javax.xml.bind.DatatypeConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ChaCha20Poly1305CipherTest {

    private static final Logger LOGGER = LogManager.getLogger();

    public static Stream<Arguments> provideChacha20Poly1305Vectors() {
        InputStream testVectorFile =
                JavaCipherTest.class.getClassLoader().getResourceAsStream("chachapolyssh.txt");
        assert testVectorFile != null;
        Scanner reader = new Scanner(testVectorFile);
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
        String line;
        while (reader.hasNextLine()) {
            line = reader.nextLine();

            if (line.startsWith("COUNT")) {
                line = reader.nextLine();
                byte[] key = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] iv = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] plaintext = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] ciphertext = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] mac = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                argumentsBuilder.add(Arguments.of(key, iv, plaintext, ciphertext, mac));
            }
        }
        return argumentsBuilder.build();
    }

    /**
     * Tests the encryption of ChaCha20Poly1305Vectors as described in
     * https://datatracker.ietf.org/doc/html/draft-josefsson-ssh-chacha20-poly1305-openssh-00
     *
     * @param key the used 512bit key, building K_2 and K_1
     * @param iv an initial vector, in case of chacha20-poly1305@openssh.com the sequence number
     * @param plaintext plaintext
     * @param ciphertext encrypted lengthfield + ciphertext
     * @param mac authentication tag
     */
    @ParameterizedTest(name = "Key:{0}")
    @MethodSource("provideChacha20Poly1305Vectors")
    public void testEncrypt(
            byte[] key, byte[] iv, byte[] plaintext, byte[] ciphertext, byte[] mac) {
        Security.addProvider(new BouncyCastleProvider());
        EncryptionCipher headerEncryptCipher =
                new JavaCipher(
                        EncryptionAlgorithm.CHACHA20_POLY1305_OPENSSH_COM,
                        Arrays.copyOfRange(
                                key,
                                CryptoConstants.CHACHA20_KEY_SIZE,
                                2 * CryptoConstants.CHACHA20_KEY_SIZE),
                        true);
        EncryptionCipher mainEncryptCipher =
                new ChaCha20Poly1305Cipher(
                        Arrays.copyOfRange(key, 0, CryptoConstants.CHACHA20_KEY_SIZE));

        byte[] encryptedLengthField = new byte[0], fullCiphertext = new byte[0];
        try {
            encryptedLengthField =
                    headerEncryptCipher.encrypt(ArrayConverter.intToBytes(plaintext.length, 4), iv);
            fullCiphertext = mainEncryptCipher.encrypt(plaintext, iv, encryptedLengthField);
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        byte[] computedCiphertext =
                Arrays.copyOfRange(fullCiphertext, 0, fullCiphertext.length - 16);
        byte[] computedMac =
                Arrays.copyOfRange(
                        fullCiphertext, fullCiphertext.length - 16, fullCiphertext.length);

        assertArrayEquals(Arrays.copyOfRange(ciphertext, 0, 4), encryptedLengthField);
        assertArrayEquals(Arrays.copyOfRange(ciphertext, 4, ciphertext.length), computedCiphertext);
        assertArrayEquals(mac, computedMac);
    }

    /**
     * Tests the decryption of ChaCha20Poly1305Vectors as described in
     * https://datatracker.ietf.org/doc/html/draft-josefsson-ssh-chacha20-poly1305-openssh-00
     *
     * @param key the used 512bit key, building K_2 and K_1
     * @param iv an initial vector, in case of chacha20-poly1305@openssh.com the sequence number
     * @param plaintext plaintext
     * @param ciphertext encrypted lengthfield + ciphertext
     * @param mac authentication tag
     */
    @ParameterizedTest(name = "Key:{0}")
    @MethodSource("provideChacha20Poly1305Vectors")
    public void testDecrypt(
            byte[] key, byte[] iv, byte[] plaintext, byte[] ciphertext, byte[] mac) {
        Security.addProvider(new BouncyCastleProvider());
        DecryptionCipher headerDecryptCipher =
                new JavaCipher(
                        EncryptionAlgorithm.CHACHA20_POLY1305_OPENSSH_COM,
                        Arrays.copyOfRange(
                                key,
                                CryptoConstants.CHACHA20_KEY_SIZE,
                                2 * CryptoConstants.CHACHA20_KEY_SIZE),
                        true);
        DecryptionCipher mainDecryptCipher =
                new ChaCha20Poly1305Cipher(
                        Arrays.copyOfRange(key, 0, CryptoConstants.CHACHA20_KEY_SIZE));
        byte[] encryptedLengthField = Arrays.copyOfRange(ciphertext, 0, 4);
        byte[] lengthField = new byte[0];
        byte[] computedPlaintext = new byte[0];

        byte[] authenticatedCiphertext =
                ArrayConverter.concatenate(
                        Arrays.copyOfRange(ciphertext, 4, ciphertext.length), mac);

        try {
            lengthField = headerDecryptCipher.decrypt(encryptedLengthField, iv);
            computedPlaintext =
                    mainDecryptCipher.decrypt(authenticatedCiphertext, iv, encryptedLengthField);
        } catch (CryptoException | AEADBadTagException e) {
            e.printStackTrace();
        }
        assertEquals(ArrayConverter.bytesToInt(lengthField), plaintext.length);
        assertArrayEquals(plaintext, computedPlaintext);
    }
}
