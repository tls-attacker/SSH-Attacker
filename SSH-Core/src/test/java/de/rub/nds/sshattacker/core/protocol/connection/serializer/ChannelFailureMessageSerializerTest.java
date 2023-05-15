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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelFailureMessageParserTest;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class ChannelFailureMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelFailureMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelFailureMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelFailureMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedRecipientChannelId Recipient channel identifier
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, int providedRecipientChannelId) {
        ChannelFailureMessage msg = new ChannelFailureMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_CHANNEL_FAILURE);
        msg.setRecipientChannelId(providedRecipientChannelId);
        ChannelMessageSerializer<ChannelFailureMessage> serializer =
                new ChannelMessageSerializer<>(msg);
        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
