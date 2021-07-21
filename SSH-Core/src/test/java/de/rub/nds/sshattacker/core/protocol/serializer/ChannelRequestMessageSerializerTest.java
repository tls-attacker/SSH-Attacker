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

import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.core.protocol.parser.ChannelRequestMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class ChannelRequestMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelRequestMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelRequestMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelRequestMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedRecipientChannel
     *            Recipient channel number
     * @param providedRequestType
     *            Channel request type
     * @param providedReplyWanted
     *            Value of the want reply flag
     * @param providedPayload
     *            Payload of the message
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, int providedRecipientChannel,
            ChannelRequestType providedRequestType, byte providedReplyWanted, byte[] providedPayload) {
        ChannelRequestMessage msg = new ChannelRequestMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_REQUEST.id);
        msg.setRecipientChannel(providedRecipientChannel);
        msg.setRequestType(providedRequestType.toString());
        msg.setReplyWanted(providedReplyWanted);
        msg.setPayload(providedPayload);
        ChannelRequestMessageSerializer serializer = new ChannelRequestMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
