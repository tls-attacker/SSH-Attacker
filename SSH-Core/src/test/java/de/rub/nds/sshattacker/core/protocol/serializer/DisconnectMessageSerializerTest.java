/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.protocol.parser.DisconnectMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DisconnectMessageSerializer;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class DisconnectMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the DisconnectMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return DisconnectMessageParserTest.provideTestVectors();
    }

    /**
     * Test of DisconnectMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedReason Disconnect reason code
     * @param providedDescription Disconnect reason description
     * @param providedLanguageTag Language tag string
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            DisconnectReason providedReason,
            String providedDescription,
            String providedLanguageTag) {
        DisconnectMessage msg = new DisconnectMessage();
        msg.setReasonCode(providedReason);
        msg.setDescription(providedDescription, true);
        msg.setLanguageTag(providedLanguageTag, true);
        DisconnectMessageSerializer serializer = new DisconnectMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
