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
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeReplyMessageParserTest;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class EcdhKeyExchangeReplyMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the EcdhKeyExchangeReplyMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return EcdhKeyExchangeReplyMessageParserTest.provideTestVectors();
    }

    /**
     * Test of EcdhKeyExchangeReplyMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output of the serialize() call
     * @param providedHostKeyBytesLength Length of the host key
     * @param providedHostKeyBytes Bytes of the host key
     * @param providedEphemeralPublicKeyLength Length of the ephemeral ECDH public key
     * @param providedEphemeralPublicKey Bytes of the ephemeral ECDH public key
     * @param providedSignatureLength Length of the signature
     * @param providedSignature Bytes of the signature
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            int providedHostKeyBytesLength,
            byte[] providedHostKeyBytes,
            int providedEphemeralPublicKeyLength,
            byte[] providedEphemeralPublicKey,
            int providedSignatureLength,
            byte[] providedSignature) {
        EcdhKeyExchangeReplyMessage msg = new EcdhKeyExchangeReplyMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_KEX_ECDH_REPLY);
        msg.setHostKeyBytesLength(providedHostKeyBytesLength);
        msg.setHostKeyBytes(providedHostKeyBytes);
        msg.setEphemeralPublicKeyLength(providedEphemeralPublicKeyLength);
        msg.setEphemeralPublicKey(providedEphemeralPublicKey);
        msg.setSignatureLength(providedSignatureLength);
        msg.setSignature(providedSignature);
        EcdhKeyExchangeReplyMessageSerializer serializer =
                new EcdhKeyExchangeReplyMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
