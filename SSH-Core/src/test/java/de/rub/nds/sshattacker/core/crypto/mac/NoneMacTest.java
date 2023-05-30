/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.mac;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class NoneMacTest {

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(200, "abc".repeat(20).getBytes(StandardCharsets.US_ASCII)),
                Arguments.of(0, "efg".repeat(20).getBytes(StandardCharsets.US_ASCII)),
                Arguments.of(0, new byte[0]),
                Arguments.of(500, "testing".repeat(20).getBytes(StandardCharsets.UTF_8)),
                Arguments.of(1000, "no mac".repeat(20).getBytes(StandardCharsets.UTF_8)));
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testNoneMac(int providedSequenceNr, byte[] data) {
        NoneMac macInstance = new NoneMac();
        assertEquals(MacAlgorithm.NONE, macInstance.getAlgorithm());
        byte[] macTag = macInstance.calculate(providedSequenceNr, data);
        assertArrayEquals(new byte[0], macTag);
    }
}
