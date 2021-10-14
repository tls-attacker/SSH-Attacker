/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** A set of tests for the BinaryPacket class */
public class BinaryPacketTest {
    /**
     * Provides a stream of test vectors for the BinaryPacket class
     *
     * @return A stream of test vectors to feed the testComputePaddingLength and
     *     testComputePacketLengthBlockSize unit tests
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, (byte) 8, 9, 20),
                Arguments.of(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, (byte) 32, 17, 28),
                Arguments.of(new byte[] {0}, (byte) 8, 10, 12));
    }

    /**
     * Test of method BinaryPacket::computePaddingLength
     *
     * @param providedPayload Payload of the binary packet
     * @param providedBlockSize Block size of the (simulated) cipher
     * @param expectedPaddingLength Expected padding length of the binary packet
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testComputePaddingLength(
            byte[] providedPayload, byte providedBlockSize, int expectedPaddingLength) {
        BinaryPacket binaryPacket =
                new BinaryPacket(ModifiableVariableFactory.safelySetValue(null, providedPayload));
        binaryPacket.computePaddingLength(providedBlockSize);
        assertEquals(expectedPaddingLength, binaryPacket.getPaddingLength().getValue().intValue());
    }

    /**
     * Test of method BinaryPacket::computePacketLength
     *
     * @param providedPayload Payload of the binary packet
     * @param providedBlockSize Block size of the (simulated) cipher
     * @param expectedPaddingLength Expected padding length of the binary packet (not used)
     * @param expectedPacketLength Expected packet length
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testComputePacketLengthBlockSize(
            byte[] providedPayload,
            byte providedBlockSize,
            @SuppressWarnings("unused") int expectedPaddingLength,
            int expectedPacketLength) {
        BinaryPacket binaryPacket =
                new BinaryPacket(ModifiableVariableFactory.safelySetValue(null, providedPayload));
        binaryPacket.computePaddingLength(providedBlockSize);
        binaryPacket.computePacketLength();
        assertEquals(expectedPacketLength, binaryPacket.getPacketLength().getValue().intValue());
    }
}
