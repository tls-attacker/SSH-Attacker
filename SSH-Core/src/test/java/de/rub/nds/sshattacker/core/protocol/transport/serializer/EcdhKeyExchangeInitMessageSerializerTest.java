/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeInitMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.EcdhKeyExchangeInitMessageSerializer;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

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
     * @param providedPublicKeyLength Length of the public key
     * @param providedPublicKey Bytes of the public key
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes, int providedPublicKeyLength, byte[] providedPublicKey) {
        EcdhKeyExchangeInitMessage msg = new EcdhKeyExchangeInitMessage();
        msg.setPublicKeyLength(providedPublicKeyLength);
        msg.setPublicKey(providedPublicKey);
        EcdhKeyExchangeInitMessageSerializer serializer =
                new EcdhKeyExchangeInitMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
