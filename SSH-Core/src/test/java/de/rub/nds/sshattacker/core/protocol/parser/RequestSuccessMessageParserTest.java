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
import de.rub.nds.sshattacker.core.protocol.connection.message.RequestSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.RequestSuccessMessageParser;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class RequestSuccessMessageParserTest {
    /**
     * Provides a stream of test vectors for the RequestSuccessMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(ArrayConverter.hexStringToByteArray("51"), new byte[0]),
                Arguments.of(ArrayConverter.hexStringToByteArray("51DEADBEEF"),
                        ArrayConverter.hexStringToByteArray("DEADBEEF")));
    }

    /**
     * Test of RequestSuccessMessageParser::parse method
     *
     * @param providedBytes
     *            Bytes to parse
     * @param expectedPayload
     *            Expected method-specific payload of the message
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, byte[] expectedPayload) {
        RequestSuccessMessageParser parser = new RequestSuccessMessageParser(0, providedBytes);
        RequestSuccessMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_REQUEST_SUCCESS.id, msg.getMessageID().getValue());
        assertArrayEquals(expectedPayload, msg.getPayload().getValue());
    }
}
