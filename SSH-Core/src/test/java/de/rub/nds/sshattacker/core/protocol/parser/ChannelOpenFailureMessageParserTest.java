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
import de.rub.nds.sshattacker.core.protocol.message.ChannelOpenFailureMessage;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ChannelOpenFailureMessageParserTest {
    /**
     * Provides a stream of test vectors for the ChannelOpenFailureMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream
                .of(Arguments.of(
                        ArrayConverter
                                .hexStringToByteArray("5C0000000000000004000000155265736F757263657320756E617661696C61626C6500000002454E"),
                        0, 4, "Resources unavailable", "EN"),
                        Arguments.of(ArrayConverter
                                .hexStringToByteArray("5C000000100000000100000009466F7262696464656E00000002454E"), 16,
                                1, "Forbidden", "EN"));
    }

    /**
     * Test of ChannelOpenFailureMessageParser::parse method
     *
     * @param providedBytes
     *            Bytes to parse
     * @param expectedRecipientChannel
     *            Expected recipient channel
     * @param expectedReasonCode
     *            Expected reason code
     * @param expectedReason
     *            Expected reason string
     * @param expectedLanguageTag
     *            Expected language tag
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, int expectedRecipientChannel, int expectedReasonCode,
            String expectedReason, String expectedLanguageTag) {
        ChannelOpenFailureMessageParser parser = new ChannelOpenFailureMessageParser(0, providedBytes);
        ChannelOpenFailureMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_CHANNEL_OPEN_FAILURE.id, msg.getMessageID().getValue());
        assertEquals(expectedRecipientChannel, msg.getRecipientChannel().getValue());
        assertEquals(expectedReasonCode, msg.getReasonCode().getValue());
        assertEquals(expectedReason, msg.getReason().getValue());
        assertEquals(expectedLanguageTag, msg.getLanguageTag().getValue());
    }
}
