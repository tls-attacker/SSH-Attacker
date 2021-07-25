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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelDataMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.parser.ChannelDataMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

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
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedRecipientChannel
     *            Recipient channel identifier
     * @param providedPayload
     *            Payload of the message
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, int providedRecipientChannel, byte[] providedPayload) {
        ChannelDataMessage msg = new ChannelDataMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_DATA.id);
        msg.setRecipientChannel(providedRecipientChannel);
        msg.setData(providedPayload);
        ChannelDataMessageSerializer serializer = new ChannelDataMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
