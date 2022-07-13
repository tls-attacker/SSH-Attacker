/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.state.SshContext;
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
     * Provides test vectors for the RsaKeyExchange according to the SSH
     * computations(testRsaKeyExchangeDecryption/ testRsaKeyExchangeEncryption) unit test from
     * rsa1024-sha1-TestVectors-KAS.txt and rsa1024-sha1-TestVectors-KAS.txt
     *
     * @param file name to load the test vectors from
     * @return A stream of test vectors for the RsaKeyExchange unit test
     */
    public static Stream<Arguments> provideTestVectors(String file) {
        InputStream testVectorFile =
                RsaKeyExchange.class.getClassLoader().getResourceAsStream(file);
        assert testVectorFile != null;
        Scanner reader = new Scanner(testVectorFile);
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
        String line;

        KeyExchangeAlgorithm keyExchangeAlgorithm = null;
        if (file.equals("rsa1024-sha1-TestVectors-KAS.txt")) {
            keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA1024_SHA1;
        } else if (file.equals("rsa2048-sha256-TestVectors-KAS.txt")) {
            keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA2048_SHA256;
        }
        BigInteger pub_modulus = null,
                pub_exponent = null,
                priv_modulus = null,
                priv_exponent = null,
                sharedSecret = null;
        byte[] ciphertext;

        while (reader.hasNextLine()) {
            line = reader.nextLine();
            if (line.startsWith("Public key")) {
                reader.nextLine();
                line = reader.nextLine();
                pub_exponent = new BigInteger(line, 16);

                reader.nextLine();
                line = reader.nextLine();
                pub_modulus = new BigInteger(line, 16);
            }

            if (line.startsWith("Private key")) {
                reader.nextLine();
                line = reader.nextLine();
                priv_exponent = new BigInteger(line, 16);

                reader.nextLine();
                line = reader.nextLine();
                priv_modulus = new BigInteger(line, 16);
                // prime1, prime2, prime_exp1, prime_exp2, coefficient
            }

            if (line.startsWith("Example")) {
                reader.nextLine();
                line = reader.nextLine();
                sharedSecret = new BigInteger(line, 16);
                reader.nextLine();
                line = reader.nextLine();
                ciphertext = DatatypeConverter.parseHexBinary(line);
                argumentsBuilder.add(
                        Arguments.of(
                                keyExchangeAlgorithm,
                                pub_exponent,
                                pub_modulus,
                                priv_exponent,
                                priv_modulus,
                                sharedSecret,
                                ciphertext));
            }
        }
        return argumentsBuilder.build();
    }

    /**
     * Provides test vectors for the RsaKeyExchange
     * (testRsaKeyExchangeDecryption/testRsaKeyExchangeEncryption) unit test from
     * rsa1024-sha1-TestVectors-KAS.txt file
     *
     * @return A stream of test vectors for the RsaKeyExchange unit test
     */
    public static Stream<Arguments> provideTestVectorsSha1() {
        return provideTestVectors("rsa1024-sha1-TestVectors-KAS.txt");
    }

    /**
     * Provides test vectors for the RsaKeyExchange
     * (testRsaKeyExchangeDecryption/testRsaKeyExchangeEncryption) unit test from
     * rsa2048-sha256-TestVectors-KAS.txt file
     *
     * @return A stream of test vectors for the RsaKeyExchange unit test
     */
    public static Stream<Arguments> provideTestVectorsSha256() {
        return provideTestVectors("rsa2048-sha256-TestVectors-KAS.txt");
    }

    /**
     * Tests the rsa key exchange decryption by computing the shared secret from the given
     * ciphertext, according to the mpint computations standarized in SSH. Thus the method tests the
     * class RsaKeyExchange.java and all underlying classes used for the decryption.
     *
     * @param keyExchangeAlgorithm used rsa key exchange algorithm
     * @param pub_key_exponent public key exponent
     * @param pub_key_modulus modulus of public key
     * @param priv_key_exponent private key exponent
     * @param priv_key_modulus modulus of private key
     * @param sharedSecret the expected shared secret
     * @param ciphertext ciphertext
     */
    @ParameterizedTest(name = "Algorithm: {0}, Private key: {3}")
    @MethodSource({"provideTestVectorsSha1", "provideTestVectorsSha256"})
    public void testRsaKeyExchangeDecryption(
            KeyExchangeAlgorithm keyExchangeAlgorithm,
            BigInteger pub_key_exponent,
            BigInteger pub_key_modulus,
            BigInteger priv_key_exponent,
            BigInteger priv_key_modulus,
            BigInteger sharedSecret,
            byte[] ciphertext) {
        RsaKeyExchange rsaKeyExchange =
                RsaKeyExchange.newInstance(new SshContext(), keyExchangeAlgorithm);
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey(pub_key_exponent, pub_key_modulus);
        CustomRsaPrivateKey privateKey =
                new CustomRsaPrivateKey(priv_key_exponent, priv_key_modulus);
        SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> keypair =
                new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey, privateKey);
        rsaKeyExchange.setTransientKey(keypair);
        rsaKeyExchange.setTransientKeyLength(keypair.getPublicKey().getModulus().bitLength());

        assertTrue(rsaKeyExchange.areParametersSet());

        assertEquals(pub_key_exponent, rsaKeyExchange.getExponent());
        assertEquals(pub_key_modulus, rsaKeyExchange.getModulus());
        assertEquals(pub_key_modulus.bitLength(), rsaKeyExchange.getTransientKeyLength());
        assertEquals(keypair, rsaKeyExchange.getTransientKey());
        assertEquals(pub_key_modulus.bitLength(), rsaKeyExchange.getTransientKeyLength());

        if (keyExchangeAlgorithm == KeyExchangeAlgorithm.RSA1024_SHA1) {
            assertEquals(160, rsaKeyExchange.getHashLength());
        }
        if (keyExchangeAlgorithm == KeyExchangeAlgorithm.RSA2048_SHA256) {
            assertEquals(256, rsaKeyExchange.getHashLength());
        }

        try {
            rsaKeyExchange.decryptSharedSecret(ciphertext);
        } catch (CryptoException e) {
            LOGGER.error(e);
        }
        assertEquals(sharedSecret, rsaKeyExchange.getSharedSecret());
    }

    /**
     * Tests the rsa key exchange encryption by computing the ciphertext from the given plaintext
     * and decrypting it again, according to the mpint computations standarized in SSH. If
     * testRsaKeyexchangeDecryption is working the right way, this method verifies the encryption
     * method of RsaKeyExchange. Thus the method test the class RsaKeyExchange.java and all
     * underlying classes.
     *
     * @param keyExchangeAlgorithm used rs key exchange algorithm
     * @param pub_key_exponent public key exponent
     * @param pub_key_modulus the modulus of public key
     * @param priv_key_exponent private key expontent
     * @param priv_key_modulus modulus of private key
     * @param sharedSecret the shared secret to be encrypted
     * @param ciphertext cipher
     */
    @ParameterizedTest(name = "Algorithm: {0}, Public key: {1}")
    @MethodSource({"provideTestVectorsSha1", "provideTestVectorsSha256"})
    public void testRsaKeyExchangeEncryption(
            KeyExchangeAlgorithm keyExchangeAlgorithm,
            BigInteger pub_key_exponent,
            BigInteger pub_key_modulus,
            BigInteger priv_key_exponent,
            BigInteger priv_key_modulus,
            BigInteger sharedSecret,
            byte[] ciphertext) {
        RsaKeyExchange rsaKeyExchange =
                RsaKeyExchange.newInstance(new SshContext(), keyExchangeAlgorithm);
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey(pub_key_exponent, pub_key_modulus);
        CustomRsaPrivateKey privateKey =
                new CustomRsaPrivateKey(priv_key_exponent, priv_key_modulus);
        SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> keypair =
                new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey, privateKey);
        rsaKeyExchange.setTransientKey(keypair);
        rsaKeyExchange.setTransientKeyLength(keypair.getPublicKey().getModulus().bitLength());

        assertTrue(rsaKeyExchange.areParametersSet());

        assertEquals(pub_key_exponent, rsaKeyExchange.getExponent());
        assertEquals(pub_key_modulus, rsaKeyExchange.getModulus());
        assertEquals(keypair, rsaKeyExchange.getTransientKey());
        assertEquals(pub_key_modulus.bitLength(), rsaKeyExchange.getTransientKeyLength());

        if (keyExchangeAlgorithm == KeyExchangeAlgorithm.RSA1024_SHA1) {
            assertEquals(160, rsaKeyExchange.getHashLength());
        }
        if (keyExchangeAlgorithm == KeyExchangeAlgorithm.RSA2048_SHA256) {
            assertEquals(256, rsaKeyExchange.getHashLength());
        }

        rsaKeyExchange.setSharedSecret(sharedSecret);
        byte[] cipher = rsaKeyExchange.encryptSharedSecret();
        try {
            rsaKeyExchange.decryptSharedSecret(cipher);
        } catch (CryptoException e) {
            LOGGER.error(e);
        }
        assertEquals(sharedSecret, rsaKeyExchange.getSharedSecret());
    }
}
