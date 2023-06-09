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
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelSuccessMessage;
import java.io.ByteArrayInputStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ChannelSuccessMessageParserTest {
    /**
     * Provides a stream of test vectors for the ChannelSuccessMessage class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(ArrayConverter.hexStringToByteArray("6300000000"), 0),
                Arguments.of(ArrayConverter.hexStringToByteArray("6300000001"), 1));
    }

    /**
     * Test of ChannelSuccessMessage::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedRecipientChannel Expected recipient channel
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, int expectedRecipientChannel) {
        ChannelSuccessMessageParser parser =
                new ChannelSuccessMessageParser(new ByteArrayInputStream(providedBytes));
        ChannelSuccessMessage msg = new ChannelSuccessMessage();
        parser.parse(msg);

        assertEquals(
                MessageIdConstant.SSH_MSG_CHANNEL_SUCCESS.getId(), msg.getMessageId().getValue());
        assertEquals(expectedRecipientChannel, msg.getRecipientChannelId().getValue());
    }
}
