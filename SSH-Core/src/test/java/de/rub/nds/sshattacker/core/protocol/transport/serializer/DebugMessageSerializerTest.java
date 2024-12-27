/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DebugMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class DebugMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the DebugMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return DebugMessageParserTest.provideTestVectors();
    }

    /**
     * Test of DebugMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedAlwaysDisplay Value of the alwaysDisplay flag
     * @param providedMessage Debug message
     * @param providedLanguageTag Language tag
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            byte providedAlwaysDisplay,
            String providedMessage,
            String providedLanguageTag) {
        DebugMessage msg = new DebugMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_DEBUG);
        msg.setAlwaysDisplay(providedAlwaysDisplay);
        msg.setMessage(providedMessage, true);
        msg.setLanguageTag(providedLanguageTag, true);
        DebugMessageSerializer serializer = new DebugMessageSerializer();

        assertArrayEquals(expectedBytes, serializer.serialize(msg));
    }
}
