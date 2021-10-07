/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeReplyMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.EcdhKeyExchangeReplyMessageSerializer;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

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
     * @param providedHostKeyLength Length of the host key
     * @param providedHostKey Bytes of the host key
     * @param providedPublicKeyLength Length of the ephemeral ECDH public key
     * @param providedPublicKey Bytes of the ephemeral ECDH public key
     * @param providedSignatureLength Length of the signature
     * @param providedSignature Bytes of the signature
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            int providedHostKeyLength,
            byte[] providedHostKey,
            int providedPublicKeyLength,
            byte[] providedPublicKey,
            int providedSignatureLength,
            byte[] providedSignature) {
        EcdhKeyExchangeReplyMessage msg = new EcdhKeyExchangeReplyMessage();
        msg.setHostKeyLength(providedHostKeyLength);
        msg.setHostKey(providedHostKey);
        msg.setEphemeralPublicKeyLength(providedPublicKeyLength);
        msg.setEphemeralPublicKey(providedPublicKey);
        msg.setSignatureLength(providedSignatureLength);
        msg.setSignature(providedSignature);
        EcdhKeyExchangeReplyMessageSerializer serializer =
                new EcdhKeyExchangeReplyMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
