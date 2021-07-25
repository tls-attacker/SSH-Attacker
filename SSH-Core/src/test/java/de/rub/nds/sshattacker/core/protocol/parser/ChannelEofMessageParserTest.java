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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelEofMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelEofMessageParser;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ChannelEofMessageParserTest {
    /**
     * Provides a stream of test vectors for the ChannelEofMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(ArrayConverter.hexStringToByteArray("6000000000"), 0),
                Arguments.of(ArrayConverter.hexStringToByteArray("6000000001"), 1));
    }

    /**
     * Test of ChannelEofMessageParser::parse method
     *
     * @param providedBytes
     *            Bytes to parse
     * @param expectedRecipientChannel
     *            Expected recipient channel
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, int expectedRecipientChannel) {
        ChannelEofMessageParser parser = new ChannelEofMessageParser(0, providedBytes);
        ChannelEofMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_CHANNEL_EOF.id, msg.getMessageID().getValue());
        assertEquals(expectedRecipientChannel, msg.getRecipientChannel().getValue());
    }
}
