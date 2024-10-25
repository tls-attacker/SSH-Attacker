/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage;
import java.io.ByteArrayInputStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class UnimplementedMessageParserTest {
    /**
     * Provides a stream of test vectors for the UnimplementedMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(ArrayConverter.hexStringToByteArray("0300000000"), 0),
                Arguments.of(ArrayConverter.hexStringToByteArray("0300000010"), 16),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("03FFFFFFFF"),
                        Integer.parseUnsignedInt("FFFFFFFF", 16)));
    }

    /**
     * Test of UnimplementedMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedSequenceNumber Expected sequence number
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, int expectedSequenceNumber) {
        UnimplementedMessageParser parser =
                new UnimplementedMessageParser(new ByteArrayInputStream(providedBytes));
        UnimplementedMessage msg = new UnimplementedMessage();
        parser.parse(msg);

        assertEquals(
                MessageIdConstant.SSH_MSG_UNIMPLEMENTED.getId(), msg.getMessageId().getValue());
        assertEquals(expectedSequenceNumber, msg.getSequenceNumber().getValue());
    }
}
