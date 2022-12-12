/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import jakarta.xml.bind.DatatypeConverter;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openquantumsafe.Pair;

@ExtendWith(MockitoExtension.class)
public class HybridKeyExchangeTest {

        private static final Logger LOGGER = LogManager.getLogger();
        // Each KeyEncapsulation algorithm based on org.openquantumsafe.KeyEncapsulation
        // needs to be mocked for testing.
        @Spy
        org.openquantumsafe.KeyEncapsulation sntrup = new org.openquantumsafe.KeyEncapsulation("sntrup761");

        @Spy
        org.openquantumsafe.KeyEncapsulation frodokem = new org.openquantumsafe.KeyEncapsulation("FrodoKEM-1344-SHAKE");

        @InjectMocks
        FrodoKem1344KeyExchange frodokem1344Kex;

        @InjectMocks
        Sntrup761KeyExchange sntrup761Kex;

        static final Map<String, KeyExchangeAlgorithm> nameToAlgorithm;

        static {
                nameToAlgorithm = new HashMap<>();
                nameToAlgorithm.put(
                                "sntrup761x25519-sha512@openssh.com", KeyExchangeAlgorithm.SNTRUP761_X25519);
        }

        /**
         * Provides test vectors for different hybrid key exchange unit tests.
         *
         * @param mode specifies if the algorithm is tested for the client (0) or the
         *             server (1)
         * @return A stream of test vectors for the testEcdh unit test
         */
        public static Stream<Arguments> provideTestVectors(int mode) {
                InputStream testVectorFile = HybridKeyExchange.class
                                .getClassLoader()
                                .getResourceAsStream("hybridKeyExchange-TestVectors.txt");
                assert testVectorFile != null;
                try (Scanner reader = new Scanner(testVectorFile)) {
                        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
                        KeyExchangeAlgorithm currentAlgorithm = null;
                        String line;
                        while (reader.hasNextLine()) {
                                line = reader.nextLine();
                                if (line.startsWith("[")) {
                                        line = line.replace("[", "").replace("]", "");
                                        currentAlgorithm = nameToAlgorithm.get(line);
                                } else if (line.startsWith("Count")) {
                                        line = reader.nextLine();
                                        byte[] privKeyEncapsulation = DatatypeConverter
                                                        .parseHexBinary(line.split(" = ")[1]);
                                        line = reader.nextLine();
                                        byte[] pubKeyEncaspulation = DatatypeConverter
                                                        .parseHexBinary(line.split(" = ")[1]);
                                        line = reader.nextLine();
                                        byte[] cyphertextEncapsulation = DatatypeConverter
                                                        .parseHexBinary(line.split(" = ")[1]);
                                        line = reader.nextLine();
                                        byte[] sharedSecretEncapsulation = DatatypeConverter
                                                        .parseHexBinary(line.split(" = ")[1]);
                                        line = reader.nextLine();
                                        byte[] privKeyAgreement = DatatypeConverter
                                                        .parseHexBinary(line.split(" = ")[1]);
                                        line = reader.nextLine();
                                        byte[] pubKeyAgreement = DatatypeConverter.parseHexBinary(line.split(" = ")[1]);
                                        line = reader.nextLine();
                                        byte[] remoteKeyAgreement = DatatypeConverter
                                                        .parseHexBinary(line.split(" = ")[1]);
                                        line = reader.nextLine();
                                        byte[] sharedSecretAgreement = DatatypeConverter
                                                        .parseHexBinary(line.split(" = ")[1]);
                                        line = reader.nextLine();
                                        byte[] encodedSharedSecret = DatatypeConverter
                                                        .parseHexBinary(line.split(" = ")[1]);
                                        if (mode == 0) {
                                                argumentsBuilder.add(
                                                                Arguments.of(
                                                                                currentAlgorithm,
                                                                                pubKeyEncaspulation,
                                                                                privKeyEncapsulation,
                                                                                pubKeyAgreement,
                                                                                privKeyAgreement,
                                                                                remoteKeyAgreement,
                                                                                sharedSecretEncapsulation,
                                                                                sharedSecretAgreement,
                                                                                cyphertextEncapsulation,
                                                                                encodedSharedSecret));
                                        }
                                        if (mode == 1) {
                                                argumentsBuilder.add(
                                                                Arguments.of(
                                                                                currentAlgorithm,
                                                                                pubKeyEncaspulation,
                                                                                pubKeyAgreement,
                                                                                privKeyAgreement,
                                                                                remoteKeyAgreement,
                                                                                sharedSecretEncapsulation,
                                                                                sharedSecretAgreement,
                                                                                cyphertextEncapsulation,
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
                return provideTestVectors(0);
        }

        /**
         * provides TestVectors for the Server
         *
         * @return TestVectors for the serverside handshake
         */
        public static Stream<Arguments> provideTestVectorsServer() {
                return provideTestVectors(1);
        }

        @ParameterizedTest
        @MethodSource("provideTestVectorsClient")
        public void testHybridKeyExchangeClient(
                        KeyExchangeAlgorithm algorithm,
                        byte[] encapsulationPubKey,
                        byte[] encapsulationPrivKey,
                        byte[] agreementPubKeyClient,
                        byte[] agreementPrivKeyClient,
                        byte[] agreementPubKeyServer,
                        byte[] encapsulationSharedSecret,
                        byte[] agreementSharedSecret,
                        byte[] cyphertext,
                        byte[] encodedSharedSecret) {

                try {
                        // Inject the encapsulation Kex with the mocked key exchange into the
                        // object to test
                        Field encapsulationField = HybridKeyExchange.class.getDeclaredField("encapsulation");
                        encapsulationField.setAccessible(true);
                        HybridKeyExchange kex = null;
                        switch (algorithm) {
                                case SNTRUP761_X25519:
                                        // Mock all functionCalls of org.openquantumsafe.KeyEncapsulation
                                        doReturn(encapsulationPubKey).when(sntrup).export_public_key();
                                        doReturn(encapsulationPrivKey).when(sntrup).export_secret_key();
                                        doReturn(encapsulationSharedSecret).when(sntrup).decap_secret(cyphertext);
                                        kex = new Sntrup761X25519KeyExchange();
                                        encapsulationField.set(kex, sntrup761Kex);
                                        break;
                                case CURVE25519_FRODOKEM1344:
                                        doReturn(encapsulationPubKey).when(frodokem).export_public_key();
                                        doReturn(encapsulationPrivKey).when(frodokem).export_secret_key();
                                        doReturn(encapsulationSharedSecret).when(frodokem).decap_secret(cyphertext);
                                        kex = new Curve25519Frodokem1344KeyExchange();
                                        encapsulationField.set(kex, frodokem1344Kex);
                                default:
                                        LOGGER.error("Algorithm " + algorithm + " not supported");
                                        kex = new Sntrup761X25519KeyExchange();
                        }

                        // Set the keys
                        kex.getKeyEncapsulation().generateLocalKeyPair();
                        assertTrue(
                                        Arrays.equals(
                                                        kex.getKeyEncapsulation().getLocalKeyPair().getPublic()
                                                                        .getEncoded(),
                                                        encapsulationPubKey));
                        assertTrue(
                                        Arrays.equals(
                                                        kex.getKeyEncapsulation().getLocalKeyPair().getPrivate()
                                                                        .getEncoded(),
                                                        encapsulationPrivKey));

                        kex.getKeyAgreement().setLocalKeyPair(agreementPrivKeyClient, agreementPubKeyClient);
                        assertTrue(
                                        Arrays.equals(
                                                        kex.getKeyAgreement().getLocalKeyPair().getPublic()
                                                                        .getEncoded(),
                                                        agreementPubKeyClient));
                        assertTrue(
                                        Arrays.equals(
                                                        kex.getKeyAgreement().getLocalKeyPair().getPrivate()
                                                                        .getEncoded(),
                                                        agreementPrivKeyClient));

                        // Set public Key and Cyphertext
                        kex.getKeyEncapsulation().setEncryptedSharedSecret(cyphertext);
                        kex.getKeyAgreement().setRemotePublicKey(agreementPubKeyServer);

                        // CombineSharedSecrets
                        kex.combineSharedSecrets();
                        assertTrue(
                                        Arrays.equals(
                                                        agreementSharedSecret,
                                                        ArrayConverter.bigIntegerToByteArray(
                                                                        kex.getKeyAgreement().getSharedSecret())));
                        assertTrue(
                                        Arrays.equals(
                                                        encapsulationSharedSecret,
                                                        ArrayConverter.bigIntegerToByteArray(
                                                                        kex.getKeyEncapsulation().getSharedSecret())));
                        assertTrue(
                                        Arrays.equals(
                                                        encodedSharedSecret,
                                                        ArrayConverter.bigIntegerToByteArray(kex.getSharedSecret())));
                } catch (SecurityException e) {
                        e.printStackTrace();
                } catch (NoSuchFieldException e) {
                        e.printStackTrace();
                } catch (IllegalArgumentException e) {
                        e.printStackTrace();
                } catch (IllegalAccessException e) {
                        e.printStackTrace();
                }
        }

        @ParameterizedTest
        @MethodSource("provideTestVectorsServer")
        public void testHybridKeyExchangeServer(
                        KeyExchangeAlgorithm algorithm,
                        byte[] encapsulationPubKey,
                        byte[] agreementPubKeyServer,
                        byte[] agreementPrivKeyServer,
                        byte[] agreementPubKeyClient,
                        byte[] encapsulationSharedSecret,
                        byte[] agreementSharedSecret,
                        byte[] cyphertext,
                        byte[] encodedSharedSecret) {
                try {
                        // Mock all functionCalls of org.openquantumsafe.KeyEncapsulation
                        doReturn(new Pair<byte[], byte[]>(cyphertext, encapsulationSharedSecret))
                                        .when(sntrup)
                                        .encap_secret(encapsulationPubKey);
                        // doReturn(encapsulationSharedSecret).when(sntrup).decap_secret(cyphertext);

                        // Inject the encapsulation Kex with the mocked sntrup key exchange into the
                        // object to test
                        Field encapsulationField = HybridKeyExchange.class.getDeclaredField("encapsulation");
                        encapsulationField.setAccessible(true);
                        HybridKeyExchange kex;
                        switch (algorithm) {
                                case SNTRUP761_X25519:
                                        kex = new Sntrup761X25519KeyExchange();
                                        encapsulationField.set(kex, sntrup761Kex);
                                        break;
                                default:
                                        LOGGER.error("Algorithm " + algorithm + " not supported.");
                                        kex = new Sntrup761X25519KeyExchange();
                                        break;
                        }

                        // Set Server Keys for Key Agreement and PubKeys send by the Client
                        kex.getKeyAgreement().setLocalKeyPair(agreementPrivKeyServer, agreementPubKeyServer);
                        assertTrue(
                                        Arrays.equals(
                                                        kex.getKeyAgreement().getLocalKeyPair().getPublic()
                                                                        .getEncoded(),
                                                        agreementPubKeyServer));
                        assertTrue(
                                        Arrays.equals(
                                                        kex.getKeyAgreement().getLocalKeyPair().getPrivate()
                                                                        .getEncoded(),
                                                        agreementPrivKeyServer));

                        kex.getKeyEncapsulation().setRemotePublicKey(encapsulationPubKey);
                        kex.getKeyAgreement().setRemotePublicKey(agreementPubKeyClient);

                        // generate sharedSecret and Cyphertext
                        kex.getKeyEncapsulation().encryptSharedSecret();
                        assertTrue(
                                        Arrays.equals(
                                                        encapsulationSharedSecret,
                                                        ArrayConverter.bigIntegerToByteArray(
                                                                        kex.getKeyEncapsulation().getSharedSecret())));
                        assertTrue(
                                        Arrays.equals(
                                                        cyphertext,
                                                        kex.getKeyEncapsulation().getEncryptedSharedSecret()));

                        // CombineSharedSecrets
                        kex.combineSharedSecrets();
                        assertTrue(
                                        Arrays.equals(
                                                        agreementSharedSecret,
                                                        ArrayConverter.bigIntegerToByteArray(
                                                                        kex.getKeyAgreement().getSharedSecret())));
                        assertTrue(
                                        Arrays.equals(
                                                        encapsulationSharedSecret,
                                                        ArrayConverter.bigIntegerToByteArray(
                                                                        kex.getKeyEncapsulation().getSharedSecret())));
                        assertTrue(
                                        Arrays.equals(
                                                        encodedSharedSecret,
                                                        ArrayConverter.bigIntegerToByteArray(kex.getSharedSecret())));
                } catch (SecurityException e) {
                        e.printStackTrace();
                } catch (NoSuchFieldException e) {
                        e.printStackTrace();
                } catch (IllegalArgumentException e) {
                        e.printStackTrace();
                } catch (IllegalAccessException e) {
                        e.printStackTrace();
                }
        }
}
