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
import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenSessionMessage;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class ChannelOpenSessionMessageParserTest {
    /**
     * Provides a stream of test vectors for the ChannelOpenMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "5A0000000773657373696F6E00000000FFFFFFFF000005DC"),
                        ChannelType.SESSION,
                        0,
                        Integer.parseUnsignedInt("FFFFFFFF", 16),
                        1500),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "5A000000037831310000000A000007D0000005DC"),
                        ChannelType.X11,
                        10,
                        2000,
                        1500),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "5A00000003783131FFFFFFFFFFFFFFFF000005DC"),
                        ChannelType.X11,
                        Integer.parseUnsignedInt("FFFFFFFF", 16),
                        Integer.parseUnsignedInt("FFFFFFFF", 16),
                        1500));
    }

    /**
     * Test of ChannelOpenMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedChannelType Expected channel type
     * @param expectedSenderChannel Expected sender channel index
     * @param expectedInitialWindowSize Expected initial window size
     * @param expectedMaximumPacketSize Expected maximum packet size
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes,
            ChannelType expectedChannelType,
            int expectedSenderChannel,
            int expectedInitialWindowSize,
            int expectedMaximumPacketSize) {
        ChannelOpenSessionMessageParser parser = new ChannelOpenSessionMessageParser(providedBytes);
        ChannelOpenSessionMessage msg = parser.parse();

        assertEquals(MessageIdConstant.SSH_MSG_CHANNEL_OPEN.getId(), msg.getMessageId().getValue());
        assertEquals(expectedChannelType.toString(), msg.getChannelType().getValue());
        assertEquals(expectedSenderChannel, msg.getSenderChannelId().getValue());
        assertEquals(expectedInitialWindowSize, msg.getWindowSize().getValue());
        assertEquals(expectedMaximumPacketSize, msg.getPacketSize().getValue());
    }
}
