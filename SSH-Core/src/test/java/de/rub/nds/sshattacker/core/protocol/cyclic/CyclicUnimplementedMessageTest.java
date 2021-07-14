package de.rub.nds.sshattacker.core.protocol.cyclic;

import de.rub.nds.sshattacker.core.protocol.message.UnimplementedMessage;
import de.rub.nds.sshattacker.core.protocol.parser.UnimplementedMessageParser;
import de.rub.nds.sshattacker.core.protocol.parser.UnimplementedMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.serializer.UnimplementedMessageSerializer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class CyclicUnimplementedMessageTest {
    /**
     * Provides a stream of test vectors for cyclic testing
     *
     * @return A stream of test vectors to feed the testCyclic unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return UnimplementedMessageParserTest.provideTestVectors()
                .map((vector) -> Arguments.of(vector.get()[0]));
    }

    /**
     * Cyclic test for parsing and serializing of UnimplementedMessage
     *
     * @param providedBytes
     *            Bytes to parse and serialize again
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testCyclic(byte[] providedBytes) {
        UnimplementedMessage msg = new UnimplementedMessageParser(0, providedBytes).parse();
        assertArrayEquals(providedBytes, new UnimplementedMessageSerializer(msg).serialize());
    }
}
