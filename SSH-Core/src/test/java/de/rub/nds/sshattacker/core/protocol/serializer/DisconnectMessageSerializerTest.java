package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.DisconnectMessage;
import de.rub.nds.sshattacker.core.protocol.parser.DisconnectMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

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
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedReason
     *            Disconnect reason code
     * @param providedDescription
     *            Disconnect reason description
     * @param providedLanguageTag
     *            Language tag string
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, DisconnectReason providedReason, String providedDescription, String providedLanguageTag) {
        DisconnectMessage msg = new DisconnectMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_DISCONNECT.id);
        msg.setReasonCode(providedReason.id);
        msg.setDescription(providedDescription);
        msg.setLanguageTag(providedLanguageTag);
        DisconnectMessageSerializer serializer = new DisconnectMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
