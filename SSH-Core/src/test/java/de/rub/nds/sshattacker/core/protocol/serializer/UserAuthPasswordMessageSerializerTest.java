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
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthPasswordMessageSerializer;
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
                        "admin", ServiceType.SSH_USERAUTH, (byte) 0x00, "admin"),
                        Arguments.of(
                                ArrayConverter
                                        .hexStringToByteArray("3200000004757365720000000C7373682D75736572617574680000000870617373776F7264000000000475736572"),
                                "user", ServiceType.SSH_USERAUTH, (byte) 0x00, "user"),
                        Arguments.of(
                                ArrayConverter
                                        .hexStringToByteArray("320000000561646D696E0000000C7373682D75736572617574680000000870617373776F7264000000000475736572"),
                                "admin", ServiceType.SSH_USERAUTH, (byte) 0x00, "user"));
    }

    /**
     * Test of UserAuthPasswordMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedUsername
     *            Username of the user to authenticate
     * @param providedServiceType
     *            Requested service to start after the user authentication was successful
     * @param providedChangePassword
     *            Value of the expectedResponse flag
     * @param providedPassword
     *            Password of the user to authenticate
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, String providedUsername, ServiceType providedServiceType,
            byte providedChangePassword, String providedPassword) {
        UserAuthPasswordMessage msg = new UserAuthPasswordMessage();
        msg.setUserName(providedUsername, true);
        msg.setServiceName(providedServiceType, true);
        msg.setChangePassword(providedChangePassword);
        msg.setPassword(providedPassword, true);
        UserAuthPasswordMessageSerializer serializer = new UserAuthPasswordMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
