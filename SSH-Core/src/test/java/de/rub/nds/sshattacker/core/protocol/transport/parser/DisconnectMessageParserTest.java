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
import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class DisconnectMessageParserTest {
    /**
     * Provides a stream of test vectors for the DisconnectMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "01000000020000001A526563656976656420756E6578706563746564207061636B657400000002454E"),
                        DisconnectReason.SSH_DISCONNECT_PROTOCOL_ERROR,
                        "Received unexpected packet",
                        "EN"),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "010000000500000014556E61626C6520746F20766572696679204D414300000002454E"),
                        DisconnectReason.SSH_DISCONNECT_MAC_ERROR,
                        "Unable to verify MAC",
                        "EN"),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "010000000C00000014546F6F206D616E7920636F6E6E656374696F6E7300000000"),
                        DisconnectReason.SSH_DISCONNECT_TOO_MANY_CONNECTIONS,
                        "Too many connections",
                        ""));
    }

    /**
     * Test of DisconnectMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedDisconnectReason Expected disconnect reason
     * @param expectedDescription Expected disconnect description
     * @param expectedLanguageTag Expected language tag
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes,
            DisconnectReason expectedDisconnectReason,
            String expectedDescription,
            String expectedLanguageTag) {
        DisconnectMessageParser parser = new DisconnectMessageParser(providedBytes);
        DisconnectMessage msg = parser.parse();

        assertEquals(MessageIdConstant.SSH_MSG_DISCONNECT.getId(), msg.getMessageId().getValue());
        assertEquals(expectedDisconnectReason.getId(), msg.getReasonCode().getValue());
        assertEquals(expectedDescription, msg.getDescription().getValue());
        assertEquals(expectedLanguageTag, msg.getLanguageTag().getValue());
    }
}
