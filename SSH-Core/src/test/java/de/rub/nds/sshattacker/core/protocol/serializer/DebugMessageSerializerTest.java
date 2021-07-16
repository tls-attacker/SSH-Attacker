/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.DebugMessage;
import de.rub.nds.sshattacker.core.protocol.parser.DebugMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

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
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedAlwaysDisplay
     *            Value of the alwaysDisplay flag
     * @param providedMessage
     *            Debug message
     * @param providedLanguageTag
     *            Language tag
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, boolean providedAlwaysDisplay, String providedMessage,
            String providedLanguageTag) {
        DebugMessage msg = new DebugMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_DEBUG.id);
        msg.setAlwaysDisplay(providedAlwaysDisplay);
        msg.setMessage(providedMessage);
        msg.setLanguageTag(providedLanguageTag);
        DebugMessageSerializer serializer = new DebugMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
