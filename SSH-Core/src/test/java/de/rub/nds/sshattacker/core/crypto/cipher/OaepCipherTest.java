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
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Scanner;
import java.util.stream.Stream;
import javax.crypto.BadPaddingException;
import javax.xml.bind.DatatypeConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class OaepCipherTest {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Provides test vectors for the OaepCipher (testRsaOaepDecryption/testRsaOaepEncryption) unit
     * test from RSA-OAEP-SHA1.txt and RSA-OAEP-SHA256.txt file
     *
     * @param file name to load the test vectors from
     * @return A stream of test vectors for the OaepCipher unit test
     */
    public static Stream<Arguments> provideTestVectors(String file) {
        InputStream testVectorFile = OaepCipher.class.getClassLoader().getResourceAsStream(file);
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
        }
        return argumentsBuilder.build();
    }

    /**
     * Provides test vectors for the OaepCipher (testRsaOaepDecryption/testRsaOaepEncryption) unit
     * test from RSA-OAEP-SHA1.txt file
     *
     * @return A stream of test vectors for the OaepCipher unit test
     */
    public static Stream<Arguments> provideTestVectorsSha1() {
        return provideTestVectors("RSA-OAEP-SHA1.txt");
    }

    /**
     * Provides test vectors for the OaepCipher (testRsaOaepDecryption/testRsaOaepEncryption) unit
     * test from RSA-OAEP-SHA256.txt file
     *
     * @return A stream of test vectors for the OaepCipher unit test
     */
    public static Stream<Arguments> provideTestVectorsSha256() {
        return provideTestVectors("RSA-OAEP-SHA256.txt");
    }

    /**
     * Tests the RSA-OAEP decryption by computing the plaintext from the provided ciphertext. Thus
     * the method tests the class OaepCipher.java and the DecryptionCipher picking of CipherFactory,
     * which are used in the RsaKeyExchange.
     *
     * @param keyExchangeAlgorithm the used rsa oaep algorithm
     * @param pub_key_exponent public key exponent
     * @param pub_key_modulus public key modulus
     * @param priv_key_exponent private key exponent
     * @param priv_key_modulus private key modulus
     * @param plaintext the expected plaintext
     * @param ciphertext provided ciphertext
     */
    @ParameterizedTest(name = "Algorithm: {0}, Private key: {3}")
    @MethodSource({"provideTestVectorsSha1", "provideTestVectorsSha256"})
    public void testRsaOaepDecryption(
            KeyExchangeAlgorithm keyExchangeAlgorithm,
            BigInteger pub_key_exponent,
            BigInteger pub_key_modulus,
            BigInteger priv_key_exponent,
            BigInteger priv_key_modulus,
            byte[] plaintext,
            byte[] ciphertext) {
        CustomRsaPrivateKey privateKey =
                new CustomRsaPrivateKey(priv_key_exponent, priv_key_modulus);
        DecryptionCipher cipher =
                CipherFactory.getDecryptionCipher(keyExchangeAlgorithm, privateKey);
        byte[] computedPlaintext = null;
        try {
            computedPlaintext = cipher.decrypt(ciphertext);
        } catch (CryptoException e) {
            LOGGER.error(e);
        }
        assertArrayEquals(plaintext, computedPlaintext);
    }

    /**
     * Tests the RSA-OAEP encryption by computing the ciphertext from the given plaintext and
     * decrypting it again. If testRsaOaepDecryption is working the right way, this method verifies
     * the encryption method of OaepCipher. Thus the method test the class OaepCipher.java and the
     * EncryptionCipher picking of CipherFactory, which are used in the RsaKeyExchange.
     *
     * @param keyExchangeAlgorithm the used rsa oaep algorithm
     * @param pub_key_exponent public key exponent
     * @param pub_key_modulus public key modulus
     * @param priv_key_exponent private key exponent
     * @param priv_key_modulus private key modulus
     * @param plaintext the expected plaintext
     * @param ciphertext provided ciphertext
     */
    @ParameterizedTest(name = "Algorithm: {0}, Public key: {1}")
    @MethodSource({"provideTestVectorsSha1", "provideTestVectorsSha256"})
    public void testRsaOaepEncryption(
            KeyExchangeAlgorithm keyExchangeAlgorithm,
            BigInteger pub_key_exponent,
            BigInteger pub_key_modulus,
            BigInteger priv_key_exponent,
            BigInteger priv_key_modulus,
            byte[] plaintext,
            byte[] ciphertext) {
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey(pub_key_exponent, pub_key_modulus);
        CustomRsaPrivateKey privateKey =
                new CustomRsaPrivateKey(priv_key_exponent, priv_key_modulus);
        SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> keypair =
                new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey, privateKey);
        EncryptionCipher encCipher =
                CipherFactory.getEncryptionCipher(keyExchangeAlgorithm, keypair.getPublicKey());
        byte[] computedCiphertext = null;
        try {
            computedCiphertext = encCipher.encrypt(plaintext);
        } catch (CryptoException e) {
            LOGGER.error(e);
        }
        DecryptionCipher decCipher =
                CipherFactory.getDecryptionCipher(
                        keyExchangeAlgorithm, keypair.getPrivateKey().get());
        byte[] computedPlaintext = null;
        try {
            computedPlaintext = decCipher.decrypt(computedCiphertext);
        } catch (CryptoException e) {
            LOGGER.error(e);
        }
        assertArrayEquals(plaintext, computedPlaintext);
    }

    @Test
    public void exceptionTesting() {
        byte[] modulus =
                ArrayConverter.hexStringToByteArray(
                        "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb");
        byte[] pub_exp = ArrayConverter.hexStringToByteArray("010001");
        byte[] priv_exp =
                ArrayConverter.hexStringToByteArray(
                        "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1");
        byte[] cipher =
                ArrayConverter.hexStringToByteArray(
                        "354fe67b4a126d5d35fe36c777791a3f7ba13def484e2d3908aff722fad468fb21696de95d0be911c2d3174f8afcc201035f7b6d8e69402de5451618c21a535fa9d7bfc5b8dd9fc243f8cf927db31322d6e881eaa91a996170e657a05a266426d98c88003f8477c1227094a0d9fa1e8c4024309ce1ecccb5210035d47ac72e8a");
        byte[] plain = ArrayConverter.hexStringToByteArray("6628194e12073db0");
        CustomRsaPublicKey publicKey =
                new CustomRsaPublicKey(new BigInteger(pub_exp), new BigInteger(modulus));
        CustomRsaPrivateKey privateKey =
                new CustomRsaPrivateKey(new BigInteger(priv_exp), new BigInteger(modulus));
        SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> keypair =
                new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey, privateKey);
        DecryptionCipher decCipher =
                CipherFactory.getDecryptionCipher(KeyExchangeAlgorithm.RSA1024_SHA1, privateKey);
        EncryptionCipher encCipher =
                CipherFactory.getEncryptionCipher(
                        KeyExchangeAlgorithm.RSA1024_SHA1, keypair.getPublicKey());
        assertThrows(
                UnsupportedOperationException.class, () -> encCipher.encrypt(plain, new byte[10]));
        assertThrows(
                UnsupportedOperationException.class,
                () -> encCipher.encrypt(plain, new byte[10], new byte[10]));
        assertThrows(
                UnsupportedOperationException.class, () -> decCipher.decrypt(cipher, new byte[10]));
        assertThrows(
                UnsupportedOperationException.class,
                () -> decCipher.decrypt(cipher, new byte[10], new byte[10]));
        OaepCipher oaepCipher =
                new OaepCipher(privateKey, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "SHA-1", "MGF1");
        assertThrows(CryptoException.class, () -> oaepCipher.decrypt(plain));
        Throwable exception = assertThrows(CryptoException.class, () -> oaepCipher.encrypt(plain));
        assertEquals(BadPaddingException.class, exception.getCause().getClass());
    }
}
