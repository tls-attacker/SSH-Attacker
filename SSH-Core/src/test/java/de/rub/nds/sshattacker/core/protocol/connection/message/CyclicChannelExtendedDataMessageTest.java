/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelExtendedDataMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelExtendedDataMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelExtendedDataMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class CyclicChannelExtendedDataMessageTest {
    /**
     * Provides a stream of test vectors for cyclic testing
     *
     * @return A stream of test vectors to feed the testCyclic unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelExtendedDataMessageParserTest.provideTestVectors()
                .map((vector) -> Arguments.of(vector.get()[0]));
    }

    /**
     * Cyclic test for parsing and serializing of ChannelExtendedDataMessages
     *
     * @param providedBytes Bytes to parse and serialize again
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testCyclic(byte[] providedBytes) {
        ChannelExtendedDataMessage msg =
                new ChannelExtendedDataMessageParser(0, providedBytes).parse();
        assertArrayEquals(providedBytes, new ChannelExtendedDataMessageSerializer(msg).serialize());
    }
}
