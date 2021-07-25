/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelWindowAdjustMessageParser;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ChannelWindowAdjustMessageParserTest {
    /**
     * Provides a stream of test vectors for the ChannelWindowAdjustMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(ArrayConverter.hexStringToByteArray("5D0000000000000400"), 0, 1024),
                Arguments.of(ArrayConverter.hexStringToByteArray("5D0000000A00000800"), 10, 2048),
                Arguments.of(ArrayConverter.hexStringToByteArray("5DFFFFFFFF000004D2"),
                        Integer.parseUnsignedInt("FFFFFFFF", 16), 1234));
    }

    /**
     * Test of ChannelWindowAdjustMessageParser::parse method
     *
     * @param providedBytes
     *            Bytes to parse
     * @param expectedRecipientChannel
     *            Expected channel number to add bytes to
     * @param expectedBytesToAdd
     *            Expected number of bytes to add to the window size
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, int expectedRecipientChannel, int expectedBytesToAdd) {
        ChannelWindowAdjustMessageParser parser = new ChannelWindowAdjustMessageParser(0, providedBytes);
        ChannelWindowAdjustMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST.id, msg.getMessageID().getValue());
        assertEquals(expectedRecipientChannel, msg.getRecipientChannel().getValue());
        assertEquals(expectedBytesToAdd, msg.getBytesToAdd().getValue());
    }
}
