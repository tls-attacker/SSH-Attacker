/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.transport.parser.DisconnectMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DisconnectMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DisconnectMessageSerializer;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class CyclicDisconnectMessageTest {
    /**
     * Provides a stream of test vectors for cyclic testing
     *
     * @return A stream of test vectors to feed the testCyclic unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return DisconnectMessageParserTest.provideTestVectors()
                .map((vector) -> Arguments.of(vector.get()[0]));
    }

    /**
     * Cyclic test for parsing and serializing of DisconnectMessage
     *
     * @param providedBytes Bytes to parse and serialize again
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testCyclic(byte[] providedBytes) {
        DisconnectMessage msg = new DisconnectMessageParser(providedBytes, 0).parse();
        assertArrayEquals(providedBytes, new DisconnectMessageSerializer(msg).serialize());
    }
}
