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
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage;
import de.rub.nds.sshattacker.core.protocol.parser.UnimplementedMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.UnimplementedMessageSerializer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class UnimplementedMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the UnimplementedMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return UnimplementedMessageParserTest.provideTestVectors();
    }

    /**
     * Test of UnimplementedMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedSequenceNumber
     *            Sequence number of the packet that got rejected
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, int providedSequenceNumber) {
        UnimplementedMessage msg = new UnimplementedMessage();
        msg.setSequenceNumber(providedSequenceNumber);
        UnimplementedMessageSerializer serializer = new UnimplementedMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
