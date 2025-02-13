/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.HashFunction;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.DatatypeConverter;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Scanner;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class RsaKeyExchangeTest {

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

        HashFunction hashFunction = null;
        if (file.equals("rsa1024-sha1-TestVectors-KAS.txt")) {
            hashFunction = HashFunction.SHA1;
        } else if (file.equals("rsa2048-sha256-TestVectors-KAS.txt")) {
            hashFunction = HashFunction.SHA256;
        }
        BigInteger publicModulus = null,
                publicExponent = null,
                privateModulus = null,
                privateExponent = null;
        byte[] sharedSecret;
        byte[] ciphertext;

        while (reader.hasNextLine()) {
            line = reader.nextLine();
            if (line.startsWith("Public key")) {
                reader.nextLine();
                line = reader.nextLine();
                publicExponent = new BigInteger(line, 16);

                reader.nextLine();
                line = reader.nextLine();
                publicModulus = new BigInteger(line, 16);
            }

            if (line.startsWith("Private key")) {
                reader.nextLine();
                line = reader.nextLine();
                privateExponent = new BigInteger(line, 16);

                reader.nextLine();
                line = reader.nextLine();
                privateModulus = new BigInteger(line, 16);
                // prime1, prime2, prime_exp1, prime_exp2, coefficient
            }

            if (line.startsWith("Example")) {
                reader.nextLine();
                line = reader.nextLine();
                sharedSecret = new BigInteger(line, 16).toByteArray();
                reader.nextLine();
                line = reader.nextLine();
                ciphertext = DatatypeConverter.parseHexBinary(line);
                argumentsBuilder.add(
                        Arguments.of(
                                hashFunction,
                                publicExponent,
                                publicModulus,
                                privateExponent,
                                privateModulus,
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
     * ciphertext, according to the mpint computations standardized in SSH. Thus, the method tests
     * the class RsaKeyExchange.java and all underlying classes used for the decryption.
     *
     * @param hashFunction used hash function
     * @param publicKeyExponent public key exponent
     * @param publicKeyModulus modulus of public key
     * @param privateKeyExponent private key exponent
     * @param privateKeyModulus modulus of private key
     * @param sharedSecret the expected shared secret
     * @param ciphertext ciphertext
     */
    @ParameterizedTest(name = "Hash function: {0}, Private key: {3}")
    @MethodSource({"provideTestVectorsSha1", "provideTestVectorsSha256"})
    public void testRsaKeyExchangeDecryption(
            HashFunction hashFunction,
            BigInteger publicKeyExponent,
            BigInteger publicKeyModulus,
            BigInteger privateKeyExponent,
            BigInteger privateKeyModulus,
            byte[] sharedSecret,
            byte[] ciphertext)
            throws CryptoException {
        RsaKeyExchange rsaKeyExchange =
                new RsaKeyExchange(publicKeyModulus.bitLength(), hashFunction);
        CustomRsaPrivateKey privateKey =
                new CustomRsaPrivateKey(privateKeyExponent, privateKeyModulus);
        rsaKeyExchange.setPrivateKey(privateKey);
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey(publicKeyExponent, publicKeyModulus);
        rsaKeyExchange.setPublicKey(publicKey);

        assertEquals(publicKeyExponent, rsaKeyExchange.getExponent());
        assertEquals(publicKeyModulus, rsaKeyExchange.getModulus());
        assertEquals(publicKeyModulus.bitLength(), rsaKeyExchange.getPublicKeySize());
        assertEquals(privateKey, rsaKeyExchange.getPrivateKey());
        assertEquals(publicKey, rsaKeyExchange.getPublicKey());
        assertEquals(hashFunction, rsaKeyExchange.getHashFunction());

        rsaKeyExchange.setEncapsulation(ciphertext);
        rsaKeyExchange.decapsulate();
        assertArrayEquals(sharedSecret, rsaKeyExchange.getSharedSecret());
    }

    /**
     * Tests the rsa key exchange encryption by computing the ciphertext from the given plaintext
     * and decrypting it again, according to the mpint computations standardized in SSH. If
     * testRsaKeyExchangeDecryption is working the right way, this method verifies the encryption
     * method of RsaKeyExchange. Thus, the method test the class RsaKeyExchange.java and all
     * underlying classes.
     *
     * @param hashFunction used hash function
     * @param publicKeyExponent public key exponent
     * @param publicKeyModulus the modulus of public key
     * @param privateKeyExponent private key exponent
     * @param privateKeyModulus modulus of private key
     * @param sharedSecret the shared secret to be encrypted
     * @param ciphertext cipher
     */
    @ParameterizedTest(name = "Hash function: {0}, Public key: {1}")
    @MethodSource({"provideTestVectorsSha1", "provideTestVectorsSha256"})
    public void testRsaKeyExchangeEncryption(
            HashFunction hashFunction,
            BigInteger publicKeyExponent,
            BigInteger publicKeyModulus,
            BigInteger privateKeyExponent,
            BigInteger privateKeyModulus,
            byte[] sharedSecret,
            byte[] ciphertext)
            throws CryptoException {
        RsaKeyExchange rsaKeyExchange =
                new RsaKeyExchange(publicKeyModulus.bitLength(), hashFunction);
        CustomRsaPrivateKey privateKey =
                new CustomRsaPrivateKey(privateKeyExponent, privateKeyModulus);
        rsaKeyExchange.setPrivateKey(privateKey);
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey(publicKeyExponent, publicKeyModulus);
        rsaKeyExchange.setPublicKey(publicKey);

        assertEquals(publicKeyExponent, rsaKeyExchange.getExponent());
        assertEquals(publicKeyModulus, rsaKeyExchange.getModulus());
        assertEquals(publicKeyModulus.bitLength(), rsaKeyExchange.getPublicKeySize());
        assertEquals(privateKey, rsaKeyExchange.getPrivateKey());
        assertEquals(publicKey, rsaKeyExchange.getPublicKey());
        assertEquals(hashFunction, rsaKeyExchange.getHashFunction());

        rsaKeyExchange.setSharedSecret(sharedSecret);
        rsaKeyExchange.encapsulate();
        rsaKeyExchange.decapsulate();
        assertArrayEquals(sharedSecret, rsaKeyExchange.getSharedSecret());
    }

    @Test
    public void exceptionTesting() {
        BigInteger modulus =
                new BigInteger(
                        "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
                        16);
        BigInteger privateExponent = new BigInteger("010001", 16);
        BigInteger publicExponent =
                new BigInteger(
                        "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1",
                        16);
        byte[] wrongInput =
                ArrayConverter.hexStringToByteArray(
                        "0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1");

        RsaKeyExchange rsaKeyExchange =
                RsaKeyExchange.newInstance(new SshContext(), KeyExchangeAlgorithm.RSA1024_SHA1);
        CustomRsaPrivateKey privateKey = new CustomRsaPrivateKey(privateExponent, modulus);
        rsaKeyExchange.setPrivateKey(privateKey);
        CustomRsaPublicKey publicKey = new CustomRsaPublicKey(publicExponent, modulus);
        rsaKeyExchange.setPublicKey(publicKey);
        assertThrows(CryptoException.class, rsaKeyExchange::decapsulate);
    }
}
