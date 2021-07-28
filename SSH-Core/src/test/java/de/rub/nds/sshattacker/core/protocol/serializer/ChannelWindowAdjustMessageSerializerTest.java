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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelWindowAdjustMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.parser.ChannelWindowAdjustMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class ChannelWindowAdjustMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelWindowAdjustMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelWindowAdjustMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelWindowAdjustMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedRecipientChannel
     *            Channel number to add bytes to
     * @param providedBytesToAdd
     *            Number of bytes to add to the window size
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, int providedRecipientChannel, int providedBytesToAdd) {
        ChannelWindowAdjustMessage msg = new ChannelWindowAdjustMessage();
        msg.setRecipientChannel(providedRecipientChannel);
        msg.setBytesToAdd(providedBytesToAdd);
        ChannelWindowAdjustMessageSerializer serializer = new ChannelWindowAdjustMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
