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

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.parser.ChannelCloseMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class ChannelCloseMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelCloseMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelCloseMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelCloseMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedRecipientChannel
     *            Recipient channel identifier
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, int providedRecipientChannel) {
        ChannelCloseMessage msg = new ChannelCloseMessage();
        msg.setRecipientChannel(providedRecipientChannel);
        ChannelMessageSerializer<ChannelCloseMessage> serializer = new ChannelMessageSerializer<>(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
