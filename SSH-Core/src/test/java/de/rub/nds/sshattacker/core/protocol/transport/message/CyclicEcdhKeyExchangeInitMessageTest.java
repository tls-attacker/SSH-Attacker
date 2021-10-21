/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeInitMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.EcdhKeyExchangeInitMessageSerializer;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class CyclicEcdhKeyExchangeInitMessageTest {
    /**
     * Provides a stream of test vectors for cyclic testing
     *
     * @return A stream of test vectors to feed the testCyclic unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return EcdhKeyExchangeInitMessageParserTest.provideTestVectors()
                .map((vector) -> Arguments.of(vector.get()[0]));
    }

    /**
     * Cyclic test for parsing and serializing of EcdhKeyExchangeInitMessages
     *
     * @param providedBytes Bytes to parse and serialize again
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testCyclic(byte[] providedBytes) {
        EcdhKeyExchangeInitMessage msg =
                new EcdhKeyExchangeInitMessageParser(providedBytes, 0).parse();
        assertArrayEquals(providedBytes, new EcdhKeyExchangeInitMessageSerializer(msg).serialize());
    }
}
