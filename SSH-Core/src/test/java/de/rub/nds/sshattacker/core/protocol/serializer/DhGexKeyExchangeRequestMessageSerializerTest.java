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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeRequestMessageSerializer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class DhGexKeyExchangeRequestMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the DhGexKeyExchangeRequestMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(ArrayConverter.hexStringToByteArray("22000002000000040000000800"), 512, 1024, 2048),
                Arguments.of(ArrayConverter.hexStringToByteArray("22000008000000080000000800"), 2048, 2048, 2048),
                Arguments.of(ArrayConverter.hexStringToByteArray("22000002000000100000002000"), 512, 4096, 8192));
    }

    /**
     * Test of DhGexKeyExchangeRequestMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedMinimalGroupSize
     *            Minimal size of the diffie hellman group provided by the server
     * @param providedPreferredGroupSize
     *            Preferred size of the diffie hellman group provided by the server
     * @param providedMaximalGroupSize
     *            Maximal size of the diffie hellman group provided by the server
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, int providedMinimalGroupSize, int providedPreferredGroupSize,
            int providedMaximalGroupSize) {
        DhGexKeyExchangeRequestMessage msg = new DhGexKeyExchangeRequestMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_REQUEST.id);
        msg.setMinimalGroupSize(providedMinimalGroupSize);
        msg.setPreferredGroupSize(providedPreferredGroupSize);
        msg.setMaximalGroupSize(providedMaximalGroupSize);
        DhGexKeyExchangeRequestMessageSerializer serializer = new DhGexKeyExchangeRequestMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
