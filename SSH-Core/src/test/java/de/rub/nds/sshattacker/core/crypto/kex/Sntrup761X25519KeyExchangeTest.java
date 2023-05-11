/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;

import jakarta.xml.bind.DatatypeConverter;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.InputStream;
import java.util.Scanner;
import java.util.stream.Stream;

public class Sntrup761X25519KeyExchangeTest {

    private enum TestMode {
        CLIENT,
        SERVER
    }

    /**
     * Provides test vectors for different hybrid key exchange unit tests.
     *
     * @param mode specifies if the algorithm is tested for the client (0) or the server (1)
     * @return A stream of test vectors for the testEcdh unit test
     */
    public static Stream<Arguments> provideTestVectors(TestMode mode) {
        InputStream testVectorFile =
                Sntrup761X25519KeyExchangeTest.class
                        .getClassLoader()
                        .getResourceAsStream("sntrup761x25519-TestVectors.txt");
        assert testVectorFile != null;
        try (Scanner reader = new Scanner(testVectorFile)) {
            Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
            KeyExchangeAlgorithm currentAlgorithm = null;
            String line;
            while (reader.hasNextLine()) {
                line = reader.nextLine();
                if (line.startsWith("Count")) {
                    line = reader.nextLine();
                    byte[] privKeyEncapsulation =
                            DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();
                    byte[] pubKeyEncaspulation =
                            DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();
                    byte[] ciphertextEncapsulation =
                            DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();
                    byte[] sharedSecretEncapsulation =
                            DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();
                    byte[] privKeyAgreement =
                            DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();
                    byte[] pubKeyAgreement = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();
                    byte[] remoteKeyAgreement =
                            DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();
                    byte[] sharedSecretAgreement =
                            DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    line = reader.nextLine();
                    byte[] encodedSharedSecret =
                            DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                    if (mode == TestMode.CLIENT) {
                        argumentsBuilder.add(
                                Arguments.of(
                                        pubKeyEncaspulation,
                                        privKeyEncapsulation,
                                        pubKeyAgreement,
                                        privKeyAgreement,
                                        remoteKeyAgreement,
                                        sharedSecretEncapsulation,
                                        sharedSecretAgreement,
                                        ciphertextEncapsulation,
                                        encodedSharedSecret));
                    }
                    if (mode == TestMode.SERVER) {
                        argumentsBuilder.add(
                                Arguments.of(
                                        pubKeyEncaspulation,
                                        pubKeyAgreement,
                                        privKeyAgreement,
                                        remoteKeyAgreement,
                                        sharedSecretEncapsulation,
                                        sharedSecretAgreement,
                                        ciphertextEncapsulation,
                                        encodedSharedSecret));
                    }
                }
            }
            return argumentsBuilder.build();
        }
    }

    /**
     * provides TestVectors for the Client
     *
     * @return TestVectors for the clientside handshake
     */
    public static Stream<Arguments> provideTestVectorsClient() {
        return provideTestVectors(TestMode.CLIENT);
    }

    /**
     * provides TestVectors for the Server
     *
     * @return TestVectors for the serverside handshake
     */
    public static Stream<Arguments> provideTestVectorsServer() {
        return provideTestVectors(TestMode.SERVER);
    }

    @ParameterizedTest
    @MethodSource("provideTestVectorsClient")
    public void testSntrup761X25519KeyExchangeClient(
            byte[] encapsulationPubKey,
            byte[] encapsulationPrivKey,
            byte[] agreementPubKeyClient,
            byte[] agreementPrivKeyClient,
            byte[] agreementPubKeyServer,
            byte[] encapsulationSharedSecret,
            byte[] agreementSharedSecret,
            byte[] ciphertext,
            byte[] encodedSharedSecret) {
        Sntrup761X25519KeyExchange kex = new Sntrup761X25519KeyExchange();
        // Set client private and public keys for both algorithms
        kex.getKeyEncapsulation().setLocalKeyPair(encapsulationPrivKey, encapsulationPubKey);
        assertArrayEquals(
                kex.getKeyEncapsulation().getLocalKeyPair().getPublic().getEncoded(),
                encapsulationPubKey);
        assertArrayEquals(
                kex.getKeyEncapsulation().getLocalKeyPair().getPrivate().getEncoded(),
                encapsulationPrivKey);

        kex.getKeyAgreement().setLocalKeyPair(agreementPrivKeyClient, agreementPubKeyClient);
        assertArrayEquals(
                kex.getKeyAgreement().getLocalKeyPair().getPublic().getEncoded(),
                agreementPubKeyClient);
        assertArrayEquals(
                kex.getKeyAgreement().getLocalKeyPair().getPrivate().getEncoded(),
                agreementPrivKeyClient);

        // Set remote public key (X25519) and encrypted shared secret (sntrup761) sent by the server
        kex.getKeyEncapsulation().setEncryptedSharedSecret(ciphertext);
        kex.getKeyAgreement().setRemotePublicKey(agreementPubKeyServer);

        // Combine shared secrets
        kex.combineSharedSecrets();
        assertArrayEquals(agreementSharedSecret, kex.getKeyAgreement().getSharedSecret());
        assertArrayEquals(encapsulationSharedSecret, kex.getKeyEncapsulation().getSharedSecret());
        assertArrayEquals(encodedSharedSecret, kex.getSharedSecret());
    }

    @ParameterizedTest
    @MethodSource("provideTestVectorsServer")
    public void testSntrup761X25519KeyExchangeServer(
            byte[] encapsulationPubKey,
            byte[] agreementPubKeyServer,
            byte[] agreementPrivKeyServer,
            byte[] agreementPubKeyClient,
            byte[] encapsulationSharedSecret,
            byte[] agreementSharedSecret,
            byte[] ciphertext,
            byte[] encodedSharedSecret) {
        Sntrup761X25519KeyExchange kex = new Sntrup761X25519KeyExchange();
        // Set private and public key for key agreement (X25519)
        kex.getKeyAgreement().setLocalKeyPair(agreementPrivKeyServer, agreementPubKeyServer);
        assertArrayEquals(
                kex.getKeyAgreement().getLocalKeyPair().getPublic().getEncoded(),
                agreementPubKeyServer);
        assertArrayEquals(
                kex.getKeyAgreement().getLocalKeyPair().getPrivate().getEncoded(),
                agreementPrivKeyServer);

        // TODO: Find a way to provide the key encapsulation with the unencrypted shared secret only
        kex.getKeyEncapsulation().setSharedSecret(encapsulationSharedSecret);
        kex.getKeyEncapsulation().setEncryptedSharedSecret(ciphertext);
        kex.getKeyEncapsulation().setRemotePublicKey(encapsulationPubKey);
        kex.getKeyAgreement().setRemotePublicKey(agreementPubKeyClient);
        assertArrayEquals(encapsulationSharedSecret, kex.getKeyEncapsulation().getSharedSecret());
        assertArrayEquals(ciphertext, kex.getKeyEncapsulation().getEncryptedSharedSecret());

        // Combine shared secrets
        kex.combineSharedSecrets();
        assertArrayEquals(agreementSharedSecret, kex.getKeyAgreement().getSharedSecret());
        assertArrayEquals(encapsulationSharedSecret, kex.getKeyEncapsulation().getSharedSecret());
        assertArrayEquals(encodedSharedSecret, kex.getSharedSecret());
    }
}
