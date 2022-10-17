/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenConfirmationMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ChannelOpenConfirmationMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelOpenConfirmationMessage class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelOpenConfirmationMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelOpenConfirmationMessage::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedRecipientChannelId Recipient channel number
     * @param providedSenderChannelId Sender channel number
     * @param providedInitialWindowSize Initial window size
     * @param providedMaximumPacketSize Maximum packet size
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            int providedRecipientChannelId,
            int providedSenderChannelId,
            int providedInitialWindowSize,
            int providedMaximumPacketSize) {
        ChannelOpenConfirmationMessage msg = new ChannelOpenConfirmationMessage();
        msg.setRecipientChannelId(providedRecipientChannelId);
        msg.setSenderChannelId(providedSenderChannelId);
        msg.setWindowSize(providedInitialWindowSize);
        msg.setPacketSize(providedMaximumPacketSize);
        ChannelOpenConfirmationMessageSerializer serializer =
                new ChannelOpenConfirmationMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
