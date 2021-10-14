/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.transport.message.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.transport.parser.BinaryPacketParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class BinaryPacketSerializerTest {
    /**
     * Provides a stream of test vectors for the BinaryPacketSerializer class
     *
     * @return A stream of test vectors to feed the testSerializeEmptyMac unit test
     */
    public static Stream<Arguments> provideTestVectorsEmptyMac() {
        return BinaryPacketParserTest.provideTestVectorsEmptyMac();
    }

    /**
     * Test of BinaryPacketSerializer::serialize without a MAC negotiated
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param packetLength Length of the binary packet
     * @param paddingLength Padding length of the binary packet
     * @param payload Payload of the binary packet
     * @param padding Padding of the binary packet
     * @param mac MAC of the binary packet
     */
    @ParameterizedTest
    @MethodSource("provideTestVectorsEmptyMac")
    public void testSerializeEmptyMac(
            byte[] expectedBytes,
            int packetLength,
            byte paddingLength,
            byte[] payload,
            byte[] padding,
            byte[] mac) {
        BinaryPacket msg = new BinaryPacket();
        msg.setPacketLength(packetLength);
        msg.setPaddingLength(paddingLength);
        msg.setPayload(payload);
        msg.setPadding(padding);
        msg.setMac(mac);
        BinaryPacketSerializer serializer = new BinaryPacketSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
