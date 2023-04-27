/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.VersionExchangeMessageParserTest;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class VersionExchangeMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the VersionExchangeMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return VersionExchangeMessageParserTest.provideTestVectors();
    }

    /**
     * Test of VersionExchangeMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedVersion Version string
     * @param providedComment Comment string
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            String providedVersion,
            String providedComment,
            String providedEndOfMessagSequence) {
        VersionExchangeMessage msg = new VersionExchangeMessage();
        msg.setVersion(providedVersion);
        msg.setComment(providedComment);
        msg.setEndOfMessageSequence("\r\n");
        VersionExchangeMessageSerializer serializer = new VersionExchangeMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
