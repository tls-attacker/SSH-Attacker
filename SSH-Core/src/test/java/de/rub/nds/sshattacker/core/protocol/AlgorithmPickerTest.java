/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import de.rub.nds.sshattacker.core.protocol.util.AlgorithmPicker;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

/** A set of tests for the AlgorithmPicker class */
public class AlgorithmPickerTest {
    /**
     * Provides a stream of test vectors for the AlgorithmPicker class
     *
     * @return A stream of test vectors to feed the testPick unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        Arrays.asList(
                                "curve25519-sha256",
                                "curve25519-sha256@libssh.org",
                                "ecdh-sha2-nistp256",
                                "ecdh-sha2-nistp384",
                                "ecdh-sha2-nistp521",
                                "diffie-hellman-group-exchange-sha256",
                                "diffie-hellman-group16-sha512",
                                "diffie-hellman-group18-sha512",
                                "diffie-hellman-group14-sha256",
                                "diffie-hellman-group14-sha1",
                                "ext-info-c"),
                        Arrays.asList(
                                "ecdh-sha2-nistp256",
                                "ecdh-sha2-nistp384",
                                "ecdh-sha2-nistp521",
                                "diffie-hellman-group-exchange-sha256",
                                "diffie-hellman-group16-sha512",
                                "diffie-hellman-group18-sha512",
                                "diffie-hellman-group14-sha256",
                                "diffie-hellman-group14-sha1",
                                "ext-info-c"),
                        "ecdh-sha2-nistp256"),
                Arguments.of(
                        Arrays.asList(
                                "curve25519-sha256@libssh.org",
                                "curve25519-sha256",
                                "ecdh-sha2-nistp256",
                                "ecdh-sha2-nistp384",
                                "ecdh-sha2-nistp521",
                                "diffie-hellman-group-exchange-sha256",
                                "diffie-hellman-group16-sha512",
                                "diffie-hellman-group18-sha512",
                                "diffie-hellman-group14-sha256",
                                "diffie-hellman-group14-sha1",
                                "ext-info-c"),
                        Arrays.asList(
                                "ecdh-sha2-nistp256",
                                "ecdh-sha2-nistp384",
                                "ecdh-sha2-nistp521",
                                "diffie-hellman-group-exchange-sha256",
                                "diffie-hellman-group16-sha512",
                                "diffie-hellman-group18-sha512",
                                "diffie-hellman-group14-sha256",
                                "diffie-hellman-group14-sha1",
                                "ext-info-c",
                                "curve25519-sha256",
                                "curve25519-sha256@libssh.org"),
                        "curve25519-sha256@libssh.org"));
    }

    /** Test of method AlgorithmPicker.pickAlgorithm with both lists being the same */
    @Test
    public void testIdentity() {
        List<String> client =
                Arrays.asList(
                        "curve25519-sha256",
                        "curve25519-sha256@libssh.org",
                        "ecdh-sha2-nistp256",
                        "ecdh-sha2-nistp384",
                        "ecdh-sha2-nistp521",
                        "diffie-hellman-group-exchange-sha256",
                        "diffie-hellman-group16-sha512",
                        "diffie-hellman-group18-sha512",
                        "diffie-hellman-group14-sha256",
                        "diffie-hellman-group14-sha1",
                        "ext-info-c");
        String picked = AlgorithmPicker.pickAlgorithm(client, client).orElse(null);
        assertEquals(client.get(0), picked);
    }

    /**
     * Test of method AlgorithmPicker.pickAlgorithm
     *
     * @param providedAlgorithmsClient List of key exchange algorithms offered by the client
     * @param providedAlgorithmsServer List of key exchange algorithms offered by the server
     * @param expectedPick Expected result of the AlgorithmPicker.pickAlgorithm call
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testPick(
            List<String> providedAlgorithmsClient,
            List<String> providedAlgorithmsServer,
            String expectedPick) {
        String picked =
                AlgorithmPicker.pickAlgorithm(providedAlgorithmsClient, providedAlgorithmsServer)
                        .orElse(null);
        assertEquals(expectedPick, picked);
    }

    /** Test of method AlgorithmPicker.pickAlgorithm without any intersection between both lists */
    @Test
    public void testNoMatch() {
        List<String> client = Collections.singletonList("curve25519-sha256");
        List<String> server = Collections.singletonList("ecdh-sha2-nistp256");

        assertFalse(AlgorithmPicker.pickAlgorithm(client, server).isPresent());
    }
}
