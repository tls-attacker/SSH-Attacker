package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.IgnoreMessage;
import de.rub.nds.sshattacker.core.protocol.parser.IgnoreMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class IgnoreMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the IgnoreMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return IgnoreMessageParserTest.provideTestVectors();
    }

    /**
     * Test of IgnoreMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedData
     *            IgnoreMessage data
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, byte[] providedData) {
        IgnoreMessage msg = new IgnoreMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_IGNORE.id);
        msg.setData(providedData);
        IgnoreMessageSerializer serializer = new IgnoreMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
