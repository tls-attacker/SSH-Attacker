/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.string;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class StringDataMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the StringDataMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return StringDataMessageParserTest.provideTestVectors();
    }

    /**
     * Test of StringDataMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedPayload Payload of the message
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, String providedPayload) {
        StringDataMessage msg = new StringDataMessage();
        msg.setData(providedPayload);
        StringDataMessageSerializer serializer = new StringDataMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
