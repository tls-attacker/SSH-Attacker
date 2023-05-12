/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.sshattacker.core.constants.EcPointFormat;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.sshattacker.core.crypto.ec.Point;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.InputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.stream.Stream;

public class EcdhKeyExchangeTest {

    public static final Map<String, NamedEcGroup> nistNameToNamedGroup;

    static {
        nistNameToNamedGroup = new HashMap<>();
        nistNameToNamedGroup.put("P-192", NamedEcGroup.SECP192R1);
        nistNameToNamedGroup.put("P-224", NamedEcGroup.SECP224R1);
        nistNameToNamedGroup.put("P-256", NamedEcGroup.SECP256R1);
        nistNameToNamedGroup.put("P-384", NamedEcGroup.SECP384R1);
        nistNameToNamedGroup.put("P-521", NamedEcGroup.SECP521R1);
        nistNameToNamedGroup.put("K-163", NamedEcGroup.SECT163K1);
        nistNameToNamedGroup.put("K-233", NamedEcGroup.SECT233K1);
        nistNameToNamedGroup.put("K-283", NamedEcGroup.SECT283K1);
        nistNameToNamedGroup.put("K-409", NamedEcGroup.SECT409K1);
        nistNameToNamedGroup.put("K-571", NamedEcGroup.SECT571K1);
        nistNameToNamedGroup.put("B-163", NamedEcGroup.SECT163R2);
        nistNameToNamedGroup.put("B-233", NamedEcGroup.SECT233R1);
        nistNameToNamedGroup.put("B-283", NamedEcGroup.SECT283R1);
        nistNameToNamedGroup.put("B-409", NamedEcGroup.SECT409R1);
        nistNameToNamedGroup.put("B-571", NamedEcGroup.SECT571R1);
    }

    /**
     * Provides test vectors for the testEcdh unit test from KAS_ECC_CDH_PrimitiveTest.txt file
     *
     * @return A stream of test vectors for the testEcdh unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        InputStream testVectorFile =
                EcdhKeyExchangeTest.class
                        .getClassLoader()
                        .getResourceAsStream("KAS_ECC_CDH_PrimitiveTest.txt");
        assert testVectorFile != null;
        Scanner reader = new Scanner(testVectorFile);
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
        NamedEcGroup currentGroup = null;
        String line;
        while (reader.hasNextLine()) {
            line = reader.nextLine();
            if (line.startsWith("[")) {
                line = line.replace("[", "").replace("]", "");
                currentGroup = nistNameToNamedGroup.get(line);
            } else if (line.startsWith("COUNT")) {
                line = reader.nextLine();
                BigInteger publicKeyXB = new BigInteger(line.split(" = ")[1], 16);
                line = reader.nextLine();
                BigInteger publicKeyYB = new BigInteger(line.split(" = ")[1], 16);
                line = reader.nextLine();
                BigInteger privateKeyA = new BigInteger(line.split(" = ")[1], 16);
                line = reader.nextLine();
                BigInteger publicKeyXA = new BigInteger(line.split(" = ")[1], 16);
                line = reader.nextLine();
                BigInteger publicKeyYA = new BigInteger(line.split(" = ")[1], 16);
                line = reader.nextLine();
                byte[] sharedSecret = new BigInteger(line.split(" = ")[1], 16).toByteArray();
                argumentsBuilder.add(
                        Arguments.of(
                                privateKeyA,
                                publicKeyXA,
                                publicKeyYA,
                                publicKeyXB,
                                publicKeyYB,
                                sharedSecret,
                                currentGroup));
            }
        }
        return argumentsBuilder.build();
    }

    /**
     * Test of EcdhKeyExchange with the provided ECDH test vectors
     *
     * @param providedPrivateKeyA Private key of local key pair
     * @param expectedPublicKeyXA Expected X coordinate for the local public key
     * @param expectedPublicKeyYA Expected Y coordinate for the local public key
     * @param providedPublicKeyXB X coordinate of the remote public key
     * @param providedPublicKeyYB Y coordinate of the remote public key
     * @param expectedSharedSecret Expected shared secret calculated using the ECDH with cofactor
     *     multiplication cryptographic primitive
     * @param group Named group to perform the calculations in
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testEcdh(
            BigInteger providedPrivateKeyA,
            BigInteger expectedPublicKeyXA,
            BigInteger expectedPublicKeyYA,
            BigInteger providedPublicKeyXB,
            BigInteger providedPublicKeyYB,
            byte[] expectedSharedSecret,
            NamedEcGroup group) {
        EcdhKeyExchange keyExchange = new EcdhKeyExchange(group);
        keyExchange.setLocalKeyPair(providedPrivateKeyA.toByteArray());
        assertEquals(
                expectedPublicKeyXA,
                keyExchange.getLocalKeyPair().getPublicKey().getWAsPoint().getFieldX().getData());
        assertEquals(
                expectedPublicKeyYA,
                keyExchange.getLocalKeyPair().getPublicKey().getWAsPoint().getFieldY().getData());
        Point publicKeyB =
                CurveFactory.getCurve(group).getPoint(providedPublicKeyXB, providedPublicKeyYB);
        keyExchange.setRemotePublicKey(
                PointFormatter.formatToByteArray(group, publicKeyB, EcPointFormat.UNCOMPRESSED));
        assertDoesNotThrow(keyExchange::computeSharedSecret);
        assertArrayEquals(expectedSharedSecret, keyExchange.getSharedSecret());
    }
}
