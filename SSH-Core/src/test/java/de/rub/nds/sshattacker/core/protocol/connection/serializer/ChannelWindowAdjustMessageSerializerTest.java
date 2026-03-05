/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelWindowAdjustMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ChannelWindowAdjustMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelWindowAdjustMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelWindowAdjustMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelWindowAdjustMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedRecipientChannelId Channel number to add bytes to
     * @param providedBytesToAdd Number of bytes to add to the window size
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes, int providedRecipientChannelId, int providedBytesToAdd) {
        ChannelWindowAdjustMessage msg = new ChannelWindowAdjustMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST);
        msg.setRecipientChannelId(providedRecipientChannelId);
        msg.setBytesToAdd(providedBytesToAdd);
        ChannelWindowAdjustMessageSerializer serializer =
                new ChannelWindowAdjustMessageSerializer();

        assertArrayEquals(expectedBytes, serializer.serialize(msg));
    }
}
