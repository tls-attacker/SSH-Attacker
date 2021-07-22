/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.parser.UserAuthFailureMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class UserAuthFailureMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the UserAuthFailureMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return UserAuthFailureMessageParserTest.provideTestVectors();
    }

    /**
     * Test of UserAuthFailureMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedAuthenticationMethods
     *            A comma-separated list of authentication methods to continue with
     * @param providedPartialSuccess
     *            Indicates whether the request sent by the client was successful or ignored
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, String providedAuthenticationMethods, byte providedPartialSuccess) {
        UserAuthFailureMessage msg = new UserAuthFailureMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_USERAUTH_FAILURE.id);
        msg.setPossibleAuthenticationMethods(providedAuthenticationMethods);
        msg.setPartialSuccess(providedPartialSuccess);
        UserAuthFailureMessageSerializer serializer = new UserAuthFailureMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
