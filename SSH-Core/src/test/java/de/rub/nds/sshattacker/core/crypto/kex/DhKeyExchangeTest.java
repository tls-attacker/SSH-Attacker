/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.sshattacker.core.constants.NamedDhGroup;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class DhKeyExchangeTest {

    static final Map<String, NamedDhGroup> nameToNamedGroup;

    static {
        nameToNamedGroup = new HashMap<>();
        nameToNamedGroup.put("GROUP1", NamedDhGroup.GROUP1);
        nameToNamedGroup.put("GROUP14", NamedDhGroup.GROUP14);
        nameToNamedGroup.put("GROUP15", NamedDhGroup.GROUP15);
        nameToNamedGroup.put("GROUP16", NamedDhGroup.GROUP16);
        nameToNamedGroup.put("GROUP17", NamedDhGroup.GROUP17);
        nameToNamedGroup.put("GROUP18", NamedDhGroup.GROUP18);
    }

    /**
     * Provides test vectors for the DH key exchange unit test from DH_TestVectors_KAS.txt file.
     *
     * @param mode specifies the needed test vector data for the belonging unit test
     * @return A stream of test vectors for the Dh key exchange unit test
     */
    public static Stream<Arguments> provideTestVectors(int mode) {
        InputStream testVectorFile =
                DhKeyExchangeTest.class
                        .getClassLoader()
                        .getResourceAsStream("DH_TestVectors_KAS.txt");
        assert testVectorFile != null;
        Scanner reader = new Scanner(testVectorFile);
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
        NamedDhGroup currentGroup = null;
        String line;
        while (reader.hasNextLine()) {
            line = reader.nextLine();
            if (line.startsWith("[")) {
                line = line.replace("[", "").replace("]", "");
                currentGroup = nameToNamedGroup.get(line);
            } else if (line.startsWith("COUNT")) {
                line = reader.nextLine();
                BigInteger privateKeyA = new BigInteger(line.split(" = ")[1], 16);
                line = reader.nextLine();
                BigInteger publicKeyA = new BigInteger(line.split(" = ")[1], 16);
                line = reader.nextLine();
                BigInteger publicKeyB = new BigInteger(line.split(" = ")[1], 16);
                line = reader.nextLine();
                byte[] sharedSecret = new BigInteger(line.split(" = ")[1], 16).toByteArray();
                if (mode == 0) {
                    argumentsBuilder.add(
                            Arguments.of(
                                    privateKeyA,
                                    publicKeyA,
                                    publicKeyB,
                                    sharedSecret,
                                    currentGroup));
                }
                if (mode == 1) {
                    argumentsBuilder.add(Arguments.of(privateKeyA, publicKeyB));
                }
                if (mode == 2) {
                    argumentsBuilder.add(Arguments.of(publicKeyB, currentGroup));
                }
            }
        }
        return argumentsBuilder.build();
    }

    /**
     * Provides test vectors for the testDh unit test from DH_TestVectors_KAS.txt file
     *
     * @return A stream of test vectors for the testDh unit test
     */
    public static Stream<Arguments> provideTestVectorsNormal() {
        return provideTestVectors(0);
    }

    /**
     * Provides limited test vectors for the testWithoutSelectedGroup unit test from
     * DH_TestVectors_KAS.txt file
     *
     * @return A stream of test vectors for the testWithoutSelectedGroup unit test
     */
    public static Stream<Arguments> provideTestVectorsNoGroup() {
        return provideTestVectors(1);
    }

    /**
     * Provides limited test vectors for the testWithoutPrivateKey unit test from
     * DH_TestVectors_KAS.txt file
     *
     * @return A stream of test vectors for the testWithoutPrivateKey unit test
     */
    public static Stream<Arguments> provideTestVectorsNoPrivateKey() {
        return provideTestVectors(2);
    }

    /**
     * Test of DhKeyExchange with the provided DH test vectors
     *
     * @param providedPrivateKeyA Private key of local key pair
     * @param expectedPublicKeyA Expected public key for the local key pair
     * @param providedPublicKeyB Remote public key
     * @param expectedSharedSecret Expected shared secret calculated using the DhKeyExchange
     * @param group Named Dh group to perform the calculations in
     */
    @ParameterizedTest
    @MethodSource("provideTestVectorsNormal")
    public void testDh(
            BigInteger providedPrivateKeyA,
            BigInteger expectedPublicKeyA,
            BigInteger providedPublicKeyB,
            byte[] expectedSharedSecret,
            NamedDhGroup group) {
        DhKeyExchange keyExchange = new DhKeyExchange(group);
        keyExchange.setLocalKeyPair(providedPrivateKeyA.toByteArray());
        assertEquals(expectedPublicKeyA, keyExchange.getLocalKeyPair().getPublicKey().getY());
        keyExchange.setRemotePublicKey(providedPublicKeyB);
        assertDoesNotThrow(keyExchange::computeSharedSecret);
        assertArrayEquals(expectedSharedSecret, keyExchange.getSharedSecret());
    }

    /**
     * Test of DhKeyExchange behaviour without selection of any group. Checks if the right
     * exceptions are thrown and that no shared secret is computed.
     *
     * @param providedPrivateKeyA Private key of local key pair
     * @param providedPublicKeyB Remote public key
     */
    @ParameterizedTest
    @MethodSource("provideTestVectorsNoGroup")
    public void testWithoutSelectedGroup(
            BigInteger providedPrivateKeyA, BigInteger providedPublicKeyB) {
        DhKeyExchange keyExchange = new DhKeyExchange();
        assertThrows(
                NullPointerException.class,
                () -> keyExchange.setLocalKeyPair(providedPrivateKeyA.toByteArray()));
        assertThrows(
                NullPointerException.class,
                () -> keyExchange.getLocalKeyPair().getPublicKey().getY());
        keyExchange.setRemotePublicKey(providedPublicKeyB);
        assertThrows(CryptoException.class, keyExchange::computeSharedSecret);
        assertNull(keyExchange.getSharedSecret());
    }

    /**
     * Test of DhKeyExchange behaviour without providing a private key . Checks if the right
     * exceptions are thrown and that no shared secret is computed.
     *
     * @param providedPublicKeyB Remote public key
     * @param group Named Dh group to perform the calculations in (not used)
     */
    @ParameterizedTest
    @MethodSource("provideTestVectorsNoPrivateKey")
    public void testWithoutPrivateKey(BigInteger providedPublicKeyB, NamedDhGroup group) {
        DhKeyExchange keyExchange = new DhKeyExchange(group);
        assertThrows(
                NullPointerException.class,
                () -> keyExchange.getLocalKeyPair().getPublicKey().getY());
        keyExchange.setRemotePublicKey(providedPublicKeyB);
        assertThrows(CryptoException.class, keyExchange::computeSharedSecret);
        assertNull(keyExchange.getSharedSecret());
    }
}
