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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.UserAuthPasswordMessage;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class UserAuthPasswordMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the UserAuthPasswordMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream
                .of(Arguments.of(
                        ArrayConverter
                                .hexStringToByteArray("320000000561646D696E0000000C7373682D75736572617574680000000870617373776F7264000000000561646D696E"),
                        "admin", "ssh-userauth", (byte) 0x00, "admin"),
                        Arguments.of(
                                ArrayConverter
                                        .hexStringToByteArray("3200000004757365720000000C7373682D75736572617574680000000870617373776F7264000000000475736572"),
                                "user", "ssh-userauth", (byte) 0x00, "user"),
                        Arguments.of(
                                ArrayConverter
                                        .hexStringToByteArray("320000000561646D696E0000000C7373682D75736572617574680000000870617373776F7264010000000475736572"),
                                "admin", "ssh-userauth", (byte) 0x01, "user"));
    }

    /**
     * Test of UserAuthPasswordMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedUsername
     *            Username of the user to authenticate
     * @param providedServiceName
     *            Requested service to start after the user authentication was successful
     * @param providedExpectedResponse
     *            Value of the expectedResponse flag
     * @param providedPassword
     *            Password of the user to authenticate
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, String providedUsername, String providedServiceName,
            byte providedExpectedResponse, String providedPassword) {
        UserAuthPasswordMessage msg = new UserAuthPasswordMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_USERAUTH_REQUEST.id);
        msg.setUsername(providedUsername);
        msg.setServicename(providedServiceName);
        msg.setExpectResponse(providedExpectedResponse);
        msg.setPassword(providedPassword);
        UserAuthPasswordMessageSerializer serializer = new UserAuthPasswordMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
