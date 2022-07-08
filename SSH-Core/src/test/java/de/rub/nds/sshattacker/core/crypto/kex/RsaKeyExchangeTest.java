/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Scanner;
import java.util.stream.Stream;
import javax.xml.bind.DatatypeConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class RsaKeyExchangeTest {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Provides test vectors for the rsa key exchange (testRsaDecryption/testRsaEncryption) unit
     * test from RSA-OAEP-SHA1.txt and RSA-OAEP-SHA256.txt file
     *
     * @param file name to load the test vectors from
     * @return A stream of test vectors for the Rsa key exchange unit test
     */
    public static Stream<Arguments> provideTestVectors(String file) {
        InputStream testVectorFile =
                RsaKeyExchange.class.getClassLoader().getResourceAsStream(file);
        assert testVectorFile != null;
        Scanner reader = new Scanner(testVectorFile);
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
        String line;

        KeyExchangeAlgorithm keyExchangeAlgorithm = null;
        if (file.equals("RSA-OAEP-SHA1.txt")) {
            keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA1024_SHA1;
        } else if (file.equals("RSA-OAEP-SHA256.txt")) {
            keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA2048_SHA256;
        }
        BigInteger pub_modulus = null,
                pub_exponent = null,
                priv_modulus = null,
                priv_exponent = null;
        byte[] plaintext, ciphertext;

        while (reader.hasNextLine()) {
            line = reader.nextLine();

            if (line.startsWith("# Example")) {

                while (reader.hasNextLine()) {
                    line = reader.nextLine();
                    if (line.startsWith("# Public key")) {
                        reader.nextLine();
                        line = reader.nextLine();
                        pub_modulus = new BigInteger(line, 16);

                        reader.nextLine();
                        line = reader.nextLine();
                        pub_exponent = new BigInteger(line, 16);
                    }

                    if (line.startsWith("# Private key")) {
                        reader.nextLine();
                        line = reader.nextLine();
                        priv_modulus = new BigInteger(line, 16);

                        reader.nextLine();
                        reader.nextLine();
                        reader.nextLine();
                        line = reader.nextLine();
                        priv_exponent = new BigInteger(line, 16);

                        // prime1, prime2, prime_exp1, prime_exp2, coefficient
                    }

                    if (line.startsWith("# OAEP Example")) {
                        reader.nextLine();
                        line = reader.nextLine();
                        plaintext = DatatypeConverter.parseHexBinary(line);
                        line = reader.nextLine();
                        if (line.startsWith("# Seed")) {
                            reader.nextLine();
                            reader.nextLine();
                        }
                        line = reader.nextLine();
                        ciphertext = DatatypeConverter.parseHexBinary(line);
                        argumentsBuilder.add(
                                Arguments.of(
                                        keyExchangeAlgorithm,
                                        pub_exponent,
                                        pub_modulus,
                                        priv_exponent,
                                        priv_modulus,
                                        plaintext,
                                        ciphertext));
                    }

                    if (line.startsWith("# =============================================")) break;
                }
            }
        }
        return argumentsBuilder.build();
    }

    /**
     * Provides test vectors for the rsa key exchange (testRsaDecryption/testRsaEncryption) unit
     * test from RSA-OAEP-SHA1.txt file
     *
     * @return A stream of test vectors for the Rsa key exchange unit test
     */
    public static Stream<Arguments> provideTestVectorsSha1() {
        return provideTestVectors("RSA-OAEP-SHA1.txt");
    }

    /**
     * Provides test vectors for the rsa key exchange (testRsaDecryption/testRsaEncryption) unit
     * test from RSA-OAEP-SHA256.txt file
     *
     * @return A stream of test vectors for the Rsa key exchange unit test
     */
    public static Stream<Arguments> provideTestVectorsSha256() {
        return provideTestVectors("RSA-OAEP-SHA256.txt");
    }

    /**
     * Tests the RSA-OAEP decryption by computing the plaintext from the provided ciphertext. Thus
     * the method test the class OaepCipher.java and the DecryptionCipher picking of CipherFactory,
     * which are used in the RsaKeyExchange. Normal RsaKeyExchange class testing can not be
     * fulfilled with these test vectors, because they are not generated in the mpint format used in
     * the Ssh protocol.
     *
     * @param keyExchangeAlgorithm the used rsa key exchange algorithm
     * @param pub_key_exponent public key exponent
     * @param pub_key_modulus public key modulus
     * @param priv_key_exponent private key exponent
     * @param priv_key_modulus private key modulus
     * @param plaintext the expected plaintext
     * @param ciphertext provided ciphertext
     */
    @ParameterizedTest
    @MethodSource({"provideTestVectorsSha1", "provideTestVectorsSha256"})
    public void testRsaDecryption(
            KeyExchangeAlgorithm keyExchangeAlgorithm,
            BigInteger pub_key_exponent,
            BigInteger pub_key_modulus,
            BigInteger priv_key_exponent,
            BigInteger priv_key_modulus,
            byte[] plaintext,
            byte[] ciphertext) {
        RsaKeyExchange keyExchange = new RsaKeyExchange(keyExchangeAlgorithm);
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey(pub_key_exponent, pub_key_modulus);
        CustomRsaPrivateKey privateKey =
                new CustomRsaPrivateKey(priv_key_exponent, priv_key_modulus);
        SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> keypair =
                new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey, privateKey);
        keyExchange.setTransientKey(keypair);
        DecryptionCipher cipher =
                CipherFactory.getDecryptionCipher(
                        keyExchangeAlgorithm, keyExchange.getTransientKey().getPrivateKey().get());
        byte[] computedPlaintext = null;
        try {
            computedPlaintext = cipher.decrypt(ciphertext);
        } catch (CryptoException e) {
            LOGGER.error(e);
        }
        assertArrayEquals(plaintext, computedPlaintext);
        LOGGER.debug(
                "Computed plaintext: " + ArrayConverter.bytesToRawHexString(computedPlaintext));
        LOGGER.debug("Expected plaintext: " + ArrayConverter.bytesToRawHexString(plaintext));
    }

    /**
     * Tests the RSA-OAEP encryption by computing the ciphertext from the given plaintext and
     * decrypting it again. If testRsaDecryption is working the right way, this method verifies the
     * encryption. Thus the method test the class OaepCipher.java and the EncryptionCipher picking
     * of CipherFactory, which are used in the RsaKeyExchange. Normal RsaKeyExchange class testing
     * can not be fulfilled with these test vectors, because they are not generated in the mpint
     * format used in the Ssh protocol.
     *
     * @param keyExchangeAlgorithm the used rsa key exchange algorithm
     * @param pub_key_exponent public key exponent
     * @param pub_key_modulus public key modulus
     * @param priv_key_exponent private key exponent
     * @param priv_key_modulus private key modulus
     * @param plaintext the expected plaintext
     * @param ciphertext provided ciphertext
     */
    @ParameterizedTest
    @MethodSource({"provideTestVectorsSha1", "provideTestVectorsSha256"})
    public void testRsaEncryption(
            KeyExchangeAlgorithm keyExchangeAlgorithm,
            BigInteger pub_key_exponent,
            BigInteger pub_key_modulus,
            BigInteger priv_key_exponent,
            BigInteger priv_key_modulus,
            byte[] plaintext,
            byte[] ciphertext) {
        RsaKeyExchange keyExchange = new RsaKeyExchange(keyExchangeAlgorithm);
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey(pub_key_exponent, pub_key_modulus);
        CustomRsaPrivateKey privateKey =
                new CustomRsaPrivateKey(priv_key_exponent, priv_key_modulus);
        SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> keypair =
                new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey, privateKey);
        keyExchange.setTransientKey(keypair);
        // Test class OaepCipher.java and the DecryptionCipher picking of CipherFactory
        EncryptionCipher encCipher =
                CipherFactory.getEncryptionCipher(
                        keyExchangeAlgorithm, keyExchange.getTransientKey().getPublicKey());
        byte[] computedCiphertext = null;
        try {
            computedCiphertext = encCipher.encrypt(plaintext);
        } catch (CryptoException e) {
            LOGGER.error(e);
        }
        LOGGER.debug("Computed cipher: " + ArrayConverter.bytesToRawHexString(computedCiphertext));

        DecryptionCipher decCipher =
                CipherFactory.getDecryptionCipher(
                        keyExchangeAlgorithm, keyExchange.getTransientKey().getPrivateKey().get());
        byte[] computedPlaintext = null;
        try {
            computedPlaintext = decCipher.decrypt(computedCiphertext);
        } catch (CryptoException e) {
            LOGGER.error(e);
        }
        LOGGER.debug("Expected plain: " + ArrayConverter.bytesToRawHexString(plaintext));
        LOGGER.debug("Computed plain: " + ArrayConverter.bytesToRawHexString(computedPlaintext));
        assertArrayEquals(plaintext, computedPlaintext);
    }

    // ToDo test the sharedSecret<-->mpint computations with generated vectors
}
