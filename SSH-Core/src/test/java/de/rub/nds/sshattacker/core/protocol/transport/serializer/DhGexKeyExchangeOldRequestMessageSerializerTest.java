/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class DhGexKeyExchangeOldRequestMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the DhGexKeyExchangeOldRequestMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(ArrayConverter.hexStringToByteArray("1E00000400"), 1024),
                Arguments.of(ArrayConverter.hexStringToByteArray("1E00000800"), 2048),
                Arguments.of(ArrayConverter.hexStringToByteArray("1E00001000"), 4096));
    }

    /**
     * Test of DhGexKeyExchangeOldRequestMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedPreferredGroupSize Preferred size of the diffie hellman group provided by the
     *     server
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, int providedPreferredGroupSize) {
        DhGexKeyExchangeOldRequestMessage msg = new DhGexKeyExchangeOldRequestMessage();
        msg.setPreferredGroupSize(providedPreferredGroupSize);
        DhGexKeyExchangeOldRequestMessageSerializer serializer =
                new DhGexKeyExchangeOldRequestMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
