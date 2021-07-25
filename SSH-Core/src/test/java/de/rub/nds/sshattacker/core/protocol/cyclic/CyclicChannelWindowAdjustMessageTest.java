/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.cyclic;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelWindowAdjustMessageParser;
import de.rub.nds.sshattacker.core.protocol.parser.ChannelWindowAdjustMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelWindowAdjustMessageSerializer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class CyclicChannelWindowAdjustMessageTest {
    /**
     * Provides a stream of test vectors for cyclic testing
     *
     * @return A stream of test vectors to feed the testCyclic unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelWindowAdjustMessageParserTest.provideTestVectors()
                .map((vector) -> Arguments.of(vector.get()[0]));
    }

    /**
     * Cyclic test for parsing and serializing of ChannelWindowAdjustMessage
     *
     * @param providedBytes
     *            Bytes to parse and serialize again
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testCyclic(byte[] providedBytes) {
        ChannelWindowAdjustMessage msg = new ChannelWindowAdjustMessageParser(0, providedBytes).parse();
        assertArrayEquals(providedBytes, new ChannelWindowAdjustMessageSerializer(msg).serialize());
    }
}
