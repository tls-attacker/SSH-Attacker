/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.DelayCompressionExtensionParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class DelayCompressionExtensionSerializerTest {
    /**
     * Provides a stream of test vectors for the DelayCompressionExtensionSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return DelayCompressionExtensionParserTest.provideTestVectors();
    }

    /**
     * Test of DelayCompressionExtensionParser::parse method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedNameLength Length of 'delay-compression' string: 17
     * @param providedName The string: 'delay-compression'
     * @param providedValueLength Length of the value of delay-compression extension
     * @param providedCompressionMethodsClientToServerLength Length of compression methods(client to server)
     * @param providedCompressionMethodsClientToServer Compression methods(client to server)
     * @param providedCompressionMethodsServerToClientLength Length of compression methods(server to client)
     * @param providedCompressionMethodsServerToClient Compression methods(server to client)
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            int providedNameLength,
            String providedName,
            int providedValueLength,
            int providedCompressionMethodsClientToServerLength,
            String providedCompressionMethodsClientToServer,
            int providedCompressionMethodsServerToClientLength,
            String providedCompressionMethodsServerToClient) {
        DelayCompressionExtension extension = new DelayCompressionExtension();
        extension.setNameLength(providedNameLength);
        extension.setName(providedName);
        extension.setValueLength(providedValueLength);
        extension.setCompressionMethodsClientToServerLength(providedCompressionMethodsClientToServerLength);
        extension.setCompressionMethodsClientToServer(providedCompressionMethodsClientToServer);
        extension.setCompressionMethodsServerToClientLength(providedCompressionMethodsServerToClientLength);
        extension.setCompressionMethodsServerToClient(providedCompressionMethodsServerToClient);

        DelayCompressionExtensionSerializer serializer =
                new DelayCompressionExtensionSerializer(extension);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
