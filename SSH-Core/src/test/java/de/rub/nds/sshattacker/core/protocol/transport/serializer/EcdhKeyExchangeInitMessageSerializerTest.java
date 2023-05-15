/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeInitMessageParserTest;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class EcdhKeyExchangeInitMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the EcdhKeyExchangeInitMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return EcdhKeyExchangeInitMessageParserTest.provideTestVectors();
    }

    /**
     * Test of EcdhKeyExchangeInitMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedEphemeralPublicKeyLength Length of the public key
     * @param providedEphemeralPublicKey Bytes of the public key
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            int providedEphemeralPublicKeyLength,
            byte[] providedEphemeralPublicKey) {
        EcdhKeyExchangeInitMessage msg = new EcdhKeyExchangeInitMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_KEX_ECDH_INIT);
        msg.setEphemeralPublicKeyLength(providedEphemeralPublicKeyLength);
        msg.setEphemeralPublicKey(providedEphemeralPublicKey);
        EcdhKeyExchangeInitMessageSerializer serializer =
                new EcdhKeyExchangeInitMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
