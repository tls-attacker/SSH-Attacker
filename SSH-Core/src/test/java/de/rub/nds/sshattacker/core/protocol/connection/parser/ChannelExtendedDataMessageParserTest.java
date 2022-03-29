/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.ExtendedChannelDataType;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ChannelExtendedDataMessageParserTest {
    /**
     * Provides a stream of test vectors for the ChannelExtendedDataMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("5F000000000000000100000004DEADBEEF"),
                        0,
                        ExtendedChannelDataType.SSH_EXTENDED_DATA_STDERR,
                        ArrayConverter.hexStringToByteArray("DEADBEEF")),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "5F000000010000000100000008DEADBEEFDEADBEEF"),
                        1,
                        ExtendedChannelDataType.SSH_EXTENDED_DATA_STDERR,
                        ArrayConverter.hexStringToByteArray("DEADBEEFDEADBEEF")),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("5FFFFFFFFF0000000100000004DEADC0DE"),
                        Integer.parseUnsignedInt("FFFFFFFF", 16),
                        ExtendedChannelDataType.SSH_EXTENDED_DATA_STDERR,
                        ArrayConverter.hexStringToByteArray("DEADC0DE")));
    }

    /**
     * Test of ChannelExtendedDataMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedRecipientChannel Expected recipient channel
     * @param expectedDataType Expected type of data
     * @param expectedPayload Expected payload of the message
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes,
            int expectedRecipientChannel,
            ExtendedChannelDataType expectedDataType,
            byte[] expectedPayload) {
        ChannelExtendedDataMessageParser parser =
                new ChannelExtendedDataMessageParser(providedBytes);
        ChannelExtendedDataMessage msg = parser.parse();

        assertEquals(
                MessageIdConstant.SSH_MSG_CHANNEL_EXTENDED_DATA.getId(),
                msg.getMessageId().getValue());
        assertEquals(expectedRecipientChannel, msg.getRecipientChannel().getValue());
        assertEquals(expectedDataType.getDataTypeCode(), msg.getDataTypeCode().getValue());
        assertArrayEquals(expectedPayload, msg.getData().getValue());
    }
}
