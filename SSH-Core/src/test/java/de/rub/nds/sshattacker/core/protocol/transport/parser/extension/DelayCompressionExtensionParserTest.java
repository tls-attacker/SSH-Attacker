/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import java.io.ByteArrayInputStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class DelayCompressionExtensionParserTest {
    /**
     * Provides a stream of test vectors for the DelayCompressionExtensionParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "0000001164656c61792d636f6d7072657373696f6e0000003c0000001a7a6c69622c6e6f6e652c7a6c6962406f70656e7373682e636f6d0000001a7a6c69622c6e6f6e652c7a6c6962406f70656e7373682e636f6d"),
                        17,
                        "delay-compression",
                        60,
                        26,
                        "zlib,none,zlib@openssh.com",
                        26,
                        "zlib,none,zlib@openssh.com"),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "0000001164656c61792d636f6d7072657373696f6e0000001600000007666f6f2c626172000000076261722c62617a"),
                        17,
                        "delay-compression",
                        22,
                        7,
                        "foo,bar",
                        7,
                        "bar,baz"));
    }

    /**
     * Test of DelayCompressionExtensionParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedNameLength Expected length of 'delay-compression' string: 17
     * @param expectedName Expected string: 'delay-compression'
     * @param expectedValueLength Expected length of the value
     * @param expectedCompressionMethodsClientToServerLength Expected length of compression
     *     methods(client to server)
     * @param expectedCompressionMethodsClientToServer Expected compression methods(client to
     *     server)
     * @param expectedCompressionMethodsServerToClientLength Expected length of compression
     *     methods(server to client)
     * @param expectedCompressionMethodsServerToClient Expected compression methods(server to
     *     client)
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes,
            int expectedNameLength,
            String expectedName,
            int expectedValueLength,
            int expectedCompressionMethodsClientToServerLength,
            String expectedCompressionMethodsClientToServer,
            int expectedCompressionMethodsServerToClientLength,
            String expectedCompressionMethodsServerToClient) {
        DelayCompressionExtension extension = new DelayCompressionExtension();
        extension.getParser(null, new ByteArrayInputStream(providedBytes)).parse(extension);
        // DelayCompressionExtensionParser parser = new DelayCompressionExtensionParser(new
        // ByteArrayInputStream(providedBytes));
        // DelayCompressionExtension extension = parser.parse();

        assertEquals(expectedNameLength, extension.getNameLength().getValue());
        assertEquals(expectedName, extension.getName().getValue());
        assertEquals(expectedValueLength, extension.getCompressionMethodsLength().getValue());
        assertEquals(
                expectedCompressionMethodsClientToServerLength,
                extension.getCompressionMethodsClientToServerLength().getValue());
        assertEquals(
                expectedCompressionMethodsClientToServer,
                extension.getCompressionMethodsClientToServer().getValue());
        assertEquals(
                expectedCompressionMethodsServerToClientLength,
                extension.getCompressionMethodsServerToClientLength().getValue());
        assertEquals(
                expectedCompressionMethodsServerToClient,
                extension.getCompressionMethodsServerToClient().getValue());
    }
}
