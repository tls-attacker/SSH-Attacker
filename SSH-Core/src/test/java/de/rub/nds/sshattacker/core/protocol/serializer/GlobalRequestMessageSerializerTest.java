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

import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestMessage;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.parser.GlobalRequestMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class GlobalRequestMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the GlobalRequestMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return GlobalRequestMessageParserTest.provideTestVectors();
    }

    /**
     * Test of GlobalRequestMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedRequestType
     *            Request type of the global request
     * @param providedWantReply
     *            Value of the wantReply flag
     * @param providedPayload
     *            Request type dependent payload of the request
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, GlobalRequestType providedRequestType, byte providedWantReply,
            byte[] providedPayload) {
        GlobalRequestMessage msg = new GlobalRequestMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_GLOBAL_REQUEST.id);
        msg.setRequestName(providedRequestType.toString());
        msg.setWantReply(providedWantReply);
        msg.setPayload(providedPayload);
        GlobalRequestMessageSerializer serializer = new GlobalRequestMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
