/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ChannelOpenConfirmationMessageParserTest {
    /**
     * Provides a stream of test vectors for the ChannelOpenConfirmationMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("5B0000000000000000FFFFFFFF000005DC"),
                        0,
                        0,
                        Integer.parseUnsignedInt("FFFFFFFF", 16),
                        1500),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("5B0000000000000064FFFFFFFF000005DC"),
                        0,
                        100,
                        Integer.parseUnsignedInt("FFFFFFFF", 16),
                        1500),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("5B0000006400000064000007D0000005DC"),
                        100,
                        100,
                        2000,
                        1500));
    }

    /**
     * Test of ChannelOpenConfirmationMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedRecipientChannel Expected recipient channel
     * @param expectedSenderChannel Expected sender channel
     * @param expectedInitialWindowSize Expected initial window size
     * @param expectedMaximumPacketSize Expected maximum packet size
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes,
            int expectedRecipientChannel,
            int expectedSenderChannel,
            int expectedInitialWindowSize,
            int expectedMaximumPacketSize) {
        ChannelOpenConfirmationMessageParser parser =
                new ChannelOpenConfirmationMessageParser(providedBytes, 0);
        ChannelOpenConfirmationMessage msg = parser.parse();

        assertEquals(
                MessageIDConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION.id,
                msg.getMessageID().getValue());
        assertEquals(expectedRecipientChannel, msg.getRecipientChannel().getValue());
        assertEquals(expectedSenderChannel, msg.getModSenderChannel().getValue());
        assertEquals(expectedInitialWindowSize, msg.getWindowSize().getValue());
        assertEquals(expectedMaximumPacketSize, msg.getPacketSize().getValue());
    }
}
