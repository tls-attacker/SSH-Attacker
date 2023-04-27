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

import jakarta.xml.bind.DatatypeConverter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.Arrays;
import java.util.Scanner;
import java.util.stream.Stream;

import javax.crypto.AEADBadTagException;

public class ChaCha20Poly1305CipherTest {

    private static final Logger LOGGER = LogManager.getLogger();

    @BeforeAll
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

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
                byte[] aad = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                line = reader.nextLine();
                byte[] mac = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                argumentsBuilder.add(Arguments.of(key, iv, plaintext, ciphertext, aad, mac));
            }
        }
        return argumentsBuilder.build();
    }

    /**
     * Tests the encryption of ChaCha20Poly1305Vectors as described in <a
     * href="https://datatracker.ietf.org/doc/html/draft-josefsson-ssh-chacha20-poly1305-openssh-00">draft-josefsson-ssh-chacha20-poly1305-openssh-00</a>
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
            byte[] key, byte[] iv, byte[] plaintext, byte[] ciphertext, byte[] aad, byte[] mac)
            throws CryptoException {
        AbstractCipher mainEncryptCipher =
                new ChaCha20Poly1305Cipher(
                        Arrays.copyOfRange(key, 0, CryptoConstants.CHACHA20_KEY_SIZE));
        byte[] fullCiphertext = mainEncryptCipher.encrypt(plaintext, iv, aad);
        byte[] computedCiphertext =
                Arrays.copyOfRange(fullCiphertext, 0, fullCiphertext.length - 16);
        byte[] computedMac =
                Arrays.copyOfRange(
                        fullCiphertext, fullCiphertext.length - 16, fullCiphertext.length);
        assertArrayEquals(ciphertext, computedCiphertext);
        assertArrayEquals(mac, computedMac);
    }

    /**
     * Tests the decryption of ChaCha20Poly1305Vectors as described in <a
     * href="https://datatracker.ietf.org/doc/html/draft-josefsson-ssh-chacha20-poly1305-openssh-00">draft-josefsson-ssh-chacha20-poly1305-openssh-00</a>
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
            byte[] key, byte[] iv, byte[] plaintext, byte[] ciphertext, byte[] aad, byte[] mac)
            throws CryptoException, AEADBadTagException {
        AbstractCipher mainDecryptCipher =
                new ChaCha20Poly1305Cipher(
                        Arrays.copyOfRange(key, 0, CryptoConstants.CHACHA20_KEY_SIZE));
        assertEquals(
                EncryptionAlgorithm.CHACHA20_POLY1305_OPENSSH_COM,
                mainDecryptCipher.getAlgorithm());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ciphertext);
            outputStream.write(mac);
        } catch (IOException e) {
            LOGGER.debug("Failure occured adding the ciphertext and tag together: " + e);
        }
        byte[] fullCiphertext = outputStream.toByteArray();
        byte[] computedPlaintext = mainDecryptCipher.decrypt(fullCiphertext, iv, aad);
        assertArrayEquals(plaintext, computedPlaintext);
    }

    @Test
    public void exceptionTesting() {
        LOGGER.info("Exception testing: ");
        AbstractCipher encryptCipher =
                new ChaCha20Poly1305Cipher(
                        ArrayConverter.hexStringToByteArray("0dd74c845517a3012ff8aa678e05159c"));
        AbstractCipher decryptCipher =
                new ChaCha20Poly1305Cipher(
                        ArrayConverter.hexStringToByteArray(
                                "c6d10362f5cae608df6e33cc124bcae2263884db63f481ab94e48b1e197f81ba"));
        byte[] cipher =
                ArrayConverter.hexStringToByteArray(
                        "ed203aedf35f3caad64e86b8a4e63043182ca70795219770f1bbacbe3e266b6c289a0d8e52b10e1072488502c759eeb86a64f81b5ee5b74a08c971c5c248a40d2856a6ad");
        byte[] plain = ArrayConverter.hexStringToByteArray("d1a4309d");
        byte[] iv = ArrayConverter.hexStringToByteArray("a32f476b");
        assertThrows(UnsupportedOperationException.class, () -> encryptCipher.encrypt(plain));
        assertThrows(UnsupportedOperationException.class, () -> encryptCipher.encrypt(plain, iv));
        assertThrows(UnsupportedOperationException.class, () -> decryptCipher.decrypt(cipher));
        assertThrows(UnsupportedOperationException.class, () -> decryptCipher.decrypt(cipher, iv));
        assertThrows(
                IllegalArgumentException.class,
                () -> decryptCipher.decrypt(cipher, iv, new byte[16]));
        byte[] newIv = ArrayConverter.hexStringToByteArray("a32f476ba32f476b");
        assertThrows(
                AEADBadTagException.class,
                () -> decryptCipher.decrypt(cipher, newIv, new byte[16]));
    }
}
