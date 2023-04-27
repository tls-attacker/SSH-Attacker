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
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class DebugMessageParserTest {
    /**
     * Provides a stream of test vectors for the DebugMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("040000000005446562756700000002454E"),
                        (byte) 0x00,
                        "Debug",
                        "EN"),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("040100000005446562756700000002454E"),
                        (byte) 0x01,
                        "Debug",
                        "EN"),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("040100000005446562756700000000"),
                        (byte) 0x01,
                        "Debug",
                        ""));
    }

    /**
     * Test of DebugMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedAlwaysDisplay Expected value for the always display flag
     * @param expectedMessage Expected debug message
     * @param expectedLanguageTag Expected language tag
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes,
            byte expectedAlwaysDisplay,
            String expectedMessage,
            String expectedLanguageTag) {
        DebugMessageParser parser = new DebugMessageParser(providedBytes);
        DebugMessage msg = parser.parse();

        assertEquals(MessageIdConstant.SSH_MSG_DEBUG.getId(), msg.getMessageId().getValue());
        assertEquals(expectedAlwaysDisplay, msg.getAlwaysDisplay().getValue());
        assertEquals(expectedMessage, msg.getMessage().getValue());
        assertEquals(expectedLanguageTag, msg.getLanguageTag().getValue());
    }
}
