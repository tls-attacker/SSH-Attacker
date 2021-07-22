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
import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.ChannelRequestMessage;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ChannelRequestMessageParserTest {
    /**
     * Provides a stream of test vectors for the ChannelRequestMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(ArrayConverter.hexStringToByteArray("6200000000000000046578656300"), 0,
                ChannelRequestType.EXEC, (byte) 0x00, new byte[0]), Arguments.of(
                ArrayConverter.hexStringToByteArray("6200000001000000057368656C6C01DEADBEEF"), 1,
                ChannelRequestType.SHELL, (byte) 0x01, ArrayConverter.hexStringToByteArray("DEADBEEF")), Arguments.of(
                ArrayConverter.hexStringToByteArray("620000000000000003656E76FFDEADBEEF"), 0, ChannelRequestType.ENV,
                (byte) 0xFF, ArrayConverter.hexStringToByteArray("DEADBEEF")));
    }

    /**
     * Test of ChannelRequestMessageParser::parse method
     *
     * @param providedBytes
     *            Bytes to parse
     * @param expectedRecipientChannel
     *            Expected recipient channel
     * @param expectedRequestType
     *            Expected channel request type
     * @param expectedReplyWanted
     *            Expected value of the want reply flag
     * @param expectedPayload
     *            Expected payload of the message
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, int expectedRecipientChannel, ChannelRequestType expectedRequestType,
            byte expectedReplyWanted, byte[] expectedPayload) {
        ChannelRequestMessageParser parser = new ChannelRequestMessageParser(0, providedBytes);
        ChannelRequestMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_CHANNEL_REQUEST.id, msg.getMessageID().getValue());
        assertEquals(expectedRecipientChannel, msg.getRecipientChannel().getValue());
        assertEquals(expectedRequestType.toString(), msg.getRequestType().getValue());
        assertEquals(expectedReplyWanted, msg.getReplyWanted().getValue());
        assertArrayEquals(expectedPayload, msg.getPayload().getValue());
    }
}
