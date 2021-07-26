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
import de.rub.nds.sshattacker.core.protocol.connection.message.RequestSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.RequestSuccessMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.parser.RequestSuccessMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class RequestSuccessMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the RequestSuccessMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return RequestSuccessMessageParserTest.provideTestVectors();
    }

    /**
     * Test of RequestSuccessMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes) {
        RequestSuccessMessage msg = new RequestSuccessMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_REQUEST_SUCCESS.id);
        RequestSuccessMessageSerializer serializer = new RequestSuccessMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
