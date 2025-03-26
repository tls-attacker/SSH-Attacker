/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenSessionMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenSessionMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ChannelOpenSessionMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelOpenMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelOpenSessionMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelOpenMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedChannelType Expected channel type
     * @param providedSenderChannelId Expected sender channel index
     * @param providedInitialWindowSize Initial window size
     * @param providedMaximumPacketSize Maximum packet size
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            ChannelType providedChannelType,
            int providedSenderChannelId,
            int providedInitialWindowSize,
            int providedMaximumPacketSize) {
        ChannelOpenSessionMessage msg = new ChannelOpenSessionMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_CHANNEL_OPEN);
        msg.setChannelType(providedChannelType.toString(), true);
        msg.setSenderChannelId(providedSenderChannelId);
        msg.setInitialWindowSize(providedInitialWindowSize);
        msg.setMaximumPacketSize(providedMaximumPacketSize);
        ChannelOpenSessionMessageSerializer serializer =
                new ChannelOpenSessionMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
