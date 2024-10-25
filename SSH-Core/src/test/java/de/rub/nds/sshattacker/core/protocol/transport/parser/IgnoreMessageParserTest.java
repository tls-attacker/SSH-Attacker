/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage;
import java.io.ByteArrayInputStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class IgnoreMessageParserTest {
    /**
     * Provides a stream of test vectors for the IgnoreMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "020000003CD926AFBBFC03C8636C04FC105A2DE1436FDC277EB391B28873BB34F813BCACF75538E02346E45EBD94B0A3FC64E11EEFB6A1E96740DB8ECEDDEC5068"),
                        ArrayConverter.hexStringToByteArray(
                                "D926AFBBFC03C8636C04FC105A2DE1436FDC277EB391B28873BB34F813BCACF75538E02346E45EBD94B0A3FC64E11EEFB6A1E96740DB8ECEDDEC5068")),
                Arguments.of(ArrayConverter.hexStringToByteArray("0200000000"), new byte[] {}));
    }

    /**
     * Test of IgnoreMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedData Expected IgnoreMessage data
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, byte[] expectedData) {
        IgnoreMessageParser parser =
                new IgnoreMessageParser(new ByteArrayInputStream(providedBytes));
        IgnoreMessage msg = new IgnoreMessage();
        parser.parse(msg);

        assertEquals(MessageIdConstant.SSH_MSG_IGNORE.getId(), msg.getMessageId().getValue());
        assertArrayEquals(expectedData, msg.getData().getValue());
    }
}
