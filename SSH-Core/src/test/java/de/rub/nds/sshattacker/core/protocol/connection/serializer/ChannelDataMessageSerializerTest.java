/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelDataMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ChannelDataMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelDataMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelDataMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelDataMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedRecipientChannel Recipient channel identifier
     * @param providedPayload Payload of the message
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes, int providedRecipientChannel, byte[] providedPayload) {
        ChannelDataMessage msg = new ChannelDataMessage();
        msg.setRecipientChannel(providedRecipientChannel);
        msg.setData(providedPayload, true);
        ChannelDataMessageSerializer serializer = new ChannelDataMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
