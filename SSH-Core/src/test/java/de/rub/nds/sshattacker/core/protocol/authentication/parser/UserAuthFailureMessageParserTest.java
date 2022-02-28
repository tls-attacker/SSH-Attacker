/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class UserAuthFailureMessageParserTest {
    /**
     * Provides a stream of test vectors for the UserAuthFailureMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "330000000E7075626C69636B65792C6E6F6E6501"),
                        "publickey,none",
                        (byte) 0x01),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "33000000137075626C69636B65792C686F7374626173656400"),
                        "publickey,hostbased",
                        (byte) 0x00),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "330000001C70617373776F72642C7075626C69636B65792C686F7374626173656400"),
                        "password,publickey,hostbased",
                        (byte) 0x00));
    }

    /**
     * Test of UserAuthFailureMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedAuthenticationMethods Expected comma-separated list of authentication methods
     *     that can continue
     * @param expectedPartialSuccess Expected value of the partialSuccess flag
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes,
            String expectedAuthenticationMethods,
            byte expectedPartialSuccess) {
        UserAuthFailureMessageParser parser = new UserAuthFailureMessageParser(providedBytes, 0);
        UserAuthFailureMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_USERAUTH_FAILURE.id, msg.getMessageID().getValue());
        assertEquals(
                expectedAuthenticationMethods, msg.getPossibleAuthenticationMethods().getValue());
        assertEquals(expectedPartialSuccess, msg.getPartialSuccess().getValue());
    }
}
