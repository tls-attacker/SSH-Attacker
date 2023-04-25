/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.ServerSigAlgsExtensionParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class ServerSigAlgsExtensionSerializerTest {
    /**
     * Provides a stream of test vectors for the ServerSigAlgsExtensionSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ServerSigAlgsExtensionParserTest.provideTestVectors();
    }

    /**
     * Test of KeyExchangeInitMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedNameLength Length of the string 'server-sig-algs': 15
     * @param providedName The String 'server-sig-algs'
     * @param providedValueLength Length of the value of server-sig-algs extension
     * @param providedValue Value of server-sig-algs extension
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            int providedNameLength,
            String providedName,
            int providedValueLength,
            String providedValue) {
        ServerSigAlgsExtension extension = new ServerSigAlgsExtension();
        extension.setNameLength(providedNameLength);
        extension.setName(providedName);
        extension.setValueLength(providedValueLength);
        extension.setAcceptedPublicKeyAlgorithms(providedValue);

        ServerSigAlgsExtensionSerializer serializer = new ServerSigAlgsExtensionSerializer(extension);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}

