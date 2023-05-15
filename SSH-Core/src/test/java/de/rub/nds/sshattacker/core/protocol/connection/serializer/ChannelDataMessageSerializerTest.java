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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelDataMessageParserTest;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class ChannelDataMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelDataMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelDataMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelDataMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedRecipientChannelId Recipient channel identifier
     * @param providedPayload Payload of the message
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes, int providedRecipientChannelId, byte[] providedPayload) {
        ChannelDataMessage msg = new ChannelDataMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_CHANNEL_DATA);
        msg.setRecipientChannelId(providedRecipientChannelId);
        msg.setData(providedPayload, true);
        ChannelDataMessageSerializer serializer = new ChannelDataMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
