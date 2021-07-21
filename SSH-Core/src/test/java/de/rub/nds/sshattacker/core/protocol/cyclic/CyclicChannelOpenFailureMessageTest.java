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

import de.rub.nds.sshattacker.core.protocol.message.ChannelOpenFailureMessage;
import de.rub.nds.sshattacker.core.protocol.parser.ChannelOpenFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.parser.ChannelOpenFailureMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.serializer.ChannelOpenFailureMessageSerializer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class CyclicChannelOpenFailureMessageTest {
    /**
     * Provides a stream of test vectors for cyclic testing
     *
     * @return A stream of test vectors to feed the testCyclic unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelOpenFailureMessageParserTest.provideTestVectors()
                .map((vector) -> Arguments.of(vector.get()[0]));
    }

    /**
     * Cyclic test for parsing and serializing of ChannelOpenFailureMessages
     *
     * @param providedBytes
     *            Bytes to parse and serialize again
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testCyclic(byte[] providedBytes) {
        ChannelOpenFailureMessage msg = new ChannelOpenFailureMessageParser(0, providedBytes).parse();
        assertArrayEquals(providedBytes, new ChannelOpenFailureMessageSerializer(msg).serialize());
    }
}
