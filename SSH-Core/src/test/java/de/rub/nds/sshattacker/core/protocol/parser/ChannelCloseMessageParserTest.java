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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelCloseMessageParser;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class ChannelCloseMessageParserTest {
    /**
     * Provides a stream of test vectors for the ChannelCloseMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(ArrayConverter.hexStringToByteArray("6100000000"), 0),
                Arguments.of(ArrayConverter.hexStringToByteArray("6100000010"), 16));
    }

    /**
     * Test of ChannelCloseMessageParser::parse method
     *
     * @param providedBytes
     *            Bytes to parse
     * @param expectedRecipientChannel
     *            Expected recipient channel
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, int expectedRecipientChannel) {
        ChannelCloseMessageParser parser = new ChannelCloseMessageParser(0, providedBytes);
        ChannelCloseMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_CHANNEL_CLOSE.id, msg.getMessageID().getValue());
        assertEquals(expectedRecipientChannel, msg.getRecipientChannel().getValue());
    }
}
