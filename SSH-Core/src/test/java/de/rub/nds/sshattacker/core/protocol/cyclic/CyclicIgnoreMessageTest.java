package de.rub.nds.sshattacker.core.protocol.cyclic;

import de.rub.nds.sshattacker.core.protocol.message.IgnoreMessage;
import de.rub.nds.sshattacker.core.protocol.parser.IgnoreMessageParser;
import de.rub.nds.sshattacker.core.protocol.parser.IgnoreMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.serializer.IgnoreMessageSerializer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class CyclicIgnoreMessageTest {
    /**
     * Provides a stream of test vectors for cyclic testing
     *
     * @return A stream of test vectors to feed the testCyclic unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return IgnoreMessageParserTest.provideTestVectors()
                .map((vector) -> Arguments.of(vector.get()[0]));
    }

    /**
     * Cyclic test for parsing and serializing of EcdhKeyExchangeReplyMessage
     *
     * @param providedBytes
     *            Bytes to parse and serialize again
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testCyclic(byte[] providedBytes) {
        IgnoreMessage msg = new IgnoreMessageParser(0, providedBytes).parse();
        assertArrayEquals(providedBytes, new IgnoreMessageSerializer(msg).serialize());
    }
}
