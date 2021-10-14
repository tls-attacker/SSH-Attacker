/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ChannelOpenMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelOpenMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelOpenMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelOpenMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedChannelType Expected channel type
     * @param providedSenderChannel Expected sender channel index
     * @param providedInitialWindowSize Initial window size
     * @param providedMaximumPacketSize Maximum packet size
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            ChannelType providedChannelType,
            int providedSenderChannel,
            int providedInitialWindowSize,
            int providedMaximumPacketSize) {
        ChannelOpenMessage msg = new ChannelOpenMessage();
        msg.setChannelType(providedChannelType.toString(), true);
        msg.setSenderChannel(providedSenderChannel);
        msg.setWindowSize(providedInitialWindowSize);
        msg.setPacketSize(providedMaximumPacketSize);
        ChannelOpenMessageSerializer serializer = new ChannelOpenMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
