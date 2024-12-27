/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestSuccessMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class GlobalRequestSuccessMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the RequestSuccessMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return GlobalRequestSuccessMessageParserTest.provideTestVectors();
    }

    /**
     * Test of RequestSuccessMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, byte[] responseSpecificData) {
        GlobalRequestSuccessMessage msg = new GlobalRequestSuccessMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_REQUEST_SUCCESS);
        msg.setResponseSpecificData(responseSpecificData);
        GlobalRequestSuccessMessageSerializer serializer =
                new GlobalRequestSuccessMessageSerializer();

        assertArrayEquals(expectedBytes, serializer.serialize(msg));
    }
}
