/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.IgnoreMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class IgnoreMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the IgnoreMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return IgnoreMessageParserTest.provideTestVectors();
    }

    /**
     * Test of IgnoreMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedData IgnoreMessage data
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, byte[] providedData) {
        IgnoreMessage msg = new IgnoreMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_IGNORE);
        msg.setData(providedData, true);
        IgnoreMessageSerializer serializer = new IgnoreMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
