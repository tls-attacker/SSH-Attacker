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
import de.rub.nds.sshattacker.core.protocol.message.ChannelSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.parser.ChannelSuccessMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class ChannelSuccessMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelSuccessMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelSuccessMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelSuccessMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedRecipientChannel
     *            Recipient channel identifier
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, int providedRecipientChannel) {
        ChannelSuccessMessage msg = new ChannelSuccessMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_SUCCESS.id);
        msg.setRecipientChannel(providedRecipientChannel);
        ChannelSuccessMessageSerializer serializer = new ChannelSuccessMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
