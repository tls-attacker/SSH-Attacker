/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.mockito.Mockito.doReturn;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.OpenQuantumSafeKemNames;
import jakarta.xml.bind.DatatypeConverter;
import java.io.InputStream;
import java.lang.reflect.Field;
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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openquantumsafe.Pair;

@ExtendWith(MockitoExtension.class)
public class HybridKeyExchangeTest {

    private static final Logger LOGGER = LogManager.getLogger();
    // Each KeyEncapsulation algorithm based on org.openquantumsafe.KeyEncapsulation
    // needs to be mocked for testing.
    @Mock org.openquantumsafe.KeyEncapsulation kem;

    @InjectMocks
    OpenQuantumSafeKem sntrup761Kex = new OpenQuantumSafeKem(OpenQuantumSafeKemNames.SNTRUP761);

    @InjectMocks
    OpenQuantumSafeKem frodokem1344Kex =
            new OpenQuantumSafeKem(OpenQuantumSafeKemNames.FRODOKEM1344);

    static final Map<String, KeyExchangeAlgorithm> nameToAlgorithm;

    static {
        nameToAlgorithm = new HashMap<>();
        nameToAlgorithm.put(
                "sntrup761x25519-sha512@openssh.com", KeyExchangeAlgorithm.SNTRUP761_X25519);
        nameToAlgorithm.put(
                "curve25519-frodokem1344-sha512@ssh.com",
                KeyExchangeAlgorithm.CURVE25519_FRODOKEM1344);
    }

    /**
     * Provides test vectors for different hybrid key exchange unit tests.
     *
     * @param mode specifies if the algorithm is tested for the client (0) or the server (1)
     * @return A stream of test vectors for the testEcdh unit test
     */
    public static Stream<Arguments> provideTestVectors(int mode) {
        InputStream testVectorFile =
                HybridKeyExchange.class
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
                                        ciphertextEncapsulation,
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
            byte[] ciphertext,
            byte[] encodedSharedSecret) {

        try {

            // Inject the encapsulation Kex with the mocked key exchange into the
            // object to test
            Field encapsulationField = HybridKeyExchange.class.getDeclaredField("encapsulation");
            encapsulationField.setAccessible(true);
            HybridKeyExchange kex = null;
            // Mock all functionCalls of org.openquantumsafe.KeyEncapsulation
            doReturn(encapsulationPubKey).when(kem).export_public_key();
            doReturn(encapsulationPrivKey).when(kem).export_secret_key();
            doReturn(encapsulationSharedSecret).when(kem).decap_secret(ciphertext);
            switch (algorithm) {
                case SNTRUP761_X25519:
                    kex = new Sntrup761X25519KeyExchange(false);
                    encapsulationField.set(kex, sntrup761Kex);
                    break;
                case CURVE25519_FRODOKEM1344:
                    kex = new Curve25519Frodokem1344KeyExchange();
                    encapsulationField.set(kex, frodokem1344Kex);
                    break;
                default:
                    LOGGER.error("Algorithm " + algorithm + " not supported");
                    kex = new Sntrup761X25519KeyExchange(false);
            }

            // Set the keys
            kex.getKeyEncapsulation().generateLocalKeyPair();
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

            // Set public Key and ciphertext
            kex.getKeyEncapsulation().setEncryptedSharedSecret(ciphertext);
            kex.getKeyAgreement().setRemotePublicKey(agreementPubKeyServer);

            // CombineSharedSecrets
            kex.combineSharedSecrets();
            assertArrayEquals(
                    agreementSharedSecret,
                    ArrayConverter.bigIntegerToByteArray(kex.getKeyAgreement().getSharedSecret()));
            assertArrayEquals(
                    encapsulationSharedSecret,
                    ArrayConverter.bigIntegerToByteArray(
                            kex.getKeyEncapsulation().getSharedSecret()));
            assertArrayEquals(
                    encodedSharedSecret,
                    ArrayConverter.bigIntegerToByteArray(kex.getSharedSecret()));
        } catch (SecurityException
                | NoSuchFieldException
                | IllegalArgumentException
                | IllegalAccessException e) {
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
            byte[] ciphertext,
            byte[] encodedSharedSecret) {
        try {
            // Inject the encapsulation Kex with the mocked sntrup key exchange into the
            // object to test
            Field encapsulationField = HybridKeyExchange.class.getDeclaredField("encapsulation");
            encapsulationField.setAccessible(true);
            HybridKeyExchange kex;
            // Mock all functionCalls of org.openquantumsafe.KeyEncapsulation
            doReturn(new Pair<byte[], byte[]>(ciphertext, encapsulationSharedSecret))
                    .when(kem)
                    .encap_secret(encapsulationPubKey);
            switch (algorithm) {
                case SNTRUP761_X25519:
                    kex = new Sntrup761X25519KeyExchange(false);
                    encapsulationField.set(kex, sntrup761Kex);
                    break;
                case CURVE25519_FRODOKEM1344:
                    kex = new Curve25519Frodokem1344KeyExchange();
                    encapsulationField.set(kex, frodokem1344Kex);
                    break;
                default:
                    LOGGER.error("Algorithm " + algorithm + " not supported.");
                    kex = new Sntrup761X25519KeyExchange(false);
                    break;
            }

            // Set Server Keys for Key Agreement and PubKeys send by the Client
            kex.getKeyAgreement().setLocalKeyPair(agreementPrivKeyServer, agreementPubKeyServer);
            assertArrayEquals(
                    kex.getKeyAgreement().getLocalKeyPair().getPublic().getEncoded(),
                    agreementPubKeyServer);
            assertArrayEquals(
                    kex.getKeyAgreement().getLocalKeyPair().getPrivate().getEncoded(),
                    agreementPrivKeyServer);

            kex.getKeyEncapsulation().setRemotePublicKey(encapsulationPubKey);
            kex.getKeyAgreement().setRemotePublicKey(agreementPubKeyClient);

            // generate sharedSecret and ciphertext
            kex.getKeyEncapsulation().encryptSharedSecret();
            assertArrayEquals(
                    encapsulationSharedSecret,
                    ArrayConverter.bigIntegerToByteArray(
                            kex.getKeyEncapsulation().getSharedSecret()));
            assertArrayEquals(ciphertext, kex.getKeyEncapsulation().getEncryptedSharedSecret());

            // CombineSharedSecrets
            kex.combineSharedSecrets();
            assertArrayEquals(
                    agreementSharedSecret,
                    ArrayConverter.bigIntegerToByteArray(kex.getKeyAgreement().getSharedSecret()));
            assertArrayEquals(
                    encapsulationSharedSecret,
                    ArrayConverter.bigIntegerToByteArray(
                            kex.getKeyEncapsulation().getSharedSecret()));
            assertArrayEquals(
                    encodedSharedSecret,
                    ArrayConverter.bigIntegerToByteArray(kex.getSharedSecret()));
        } catch (SecurityException
                | NoSuchFieldException
                | IllegalArgumentException
                | IllegalAccessException e) {
            e.printStackTrace();
        }
    }
}
