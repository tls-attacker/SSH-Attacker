/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ExtensionInfoMessageParserTest {
    /**
     * Provides a stream of test vectors for the ExtensionInfoMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "07000000020000000f7365727665722d7369672d616c6773000000897373682d656432353531392c65636473612d736861322d312e332e3133322e302e31302c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e697374703532312c7273612d736861322d3531322c7273612d736861322d3235362c7373682d7273612c7373682d6473730000001164656c61792d636f6d7072657373696f6e0000001a000000097a6c69622c6e6f6e65000000097a6c69622c6e6f6e65"),
                        2,
                        15,
                        "server-sig-algs",
                        137,
                        "ssh-ed25519,ecdsa-sha2-1.3.132.0.10,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss",
                        17,
                        "delay-compression",
                        26,
                        9,
                        "zlib,none",
                        9,
                        "zlib,none"),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "07000000020000000f7365727665722d7369672d616c6773000000197273612d736861322d3235362c7273612d736861322d3531320000001164656c61792d636f6d7072657373696f6e0000001600000007666f6f2c626172000000076261722c62617a"),
                        2,
                        15,
                        "server-sig-algs",
                        25,
                        "rsa-sha2-256,rsa-sha2-512",
                        17,
                        "delay-compression",
                        22,
                        7,
                        "foo,bar",
                        7,
                        "bar,baz"));
    }

    /**
     * Test of ExtensionInfoMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedExtensionCount Expected count of the extensions
     * @param expectedNameLengthOfServerSigAlgsExtension Expected length of the string
     *     'server-sig-algs': 15
     * @param expectedNameOfServerSigAlgsExtension Expected string of server-sig-algs extension:
     *     'server-sig-algs'
     * @param expectedValueLengthOfServerSigAlgsExtension Expected length of value of
     *     server-sig-algs extension
     * @param expectedValueOfServerSigAlgsExtension Expected value of server-sig-algs extension
     * @param expectedNameLengthOfDelayCompressionExtension Expected length of the string
     *     'delay-compression': 17
     * @param expectedNameOfDelayCompressionExtension Expected string of the delay-compression
     *     extension: 'delay-compression'
     * @param expectedValueLengthOfDelayCompressionExtension Expected length of value of
     *     delay-compression extension
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
            int expectedExtensionCount,
            int expectedNameLengthOfServerSigAlgsExtension,
            String expectedNameOfServerSigAlgsExtension,
            int expectedValueLengthOfServerSigAlgsExtension,
            String expectedValueOfServerSigAlgsExtension,
            int expectedNameLengthOfDelayCompressionExtension,
            String expectedNameOfDelayCompressionExtension,
            int expectedValueLengthOfDelayCompressionExtension,
            int expectedCompressionMethodsClientToServerLength,
            String expectedCompressionMethodsClientToServer,
            int expectedCompressionMethodsServerToClientLength,
            String expectedCompressionMethodsServerToClient) {
        ExtensionInfoMessageParser parser =
                new ExtensionInfoMessageParser(new ByteArrayInputStream(providedBytes));
        ExtensionInfoMessage msg = new ExtensionInfoMessage();
        parser.parse(msg);
        List<AbstractExtension<?>> extensions = msg.getExtensions();
        ServerSigAlgsExtension serverSigAlgsExtension = (ServerSigAlgsExtension) extensions.get(0);
        DelayCompressionExtension delayCompressionExtension =
                (DelayCompressionExtension) extensions.get(1);

        assertEquals(expectedExtensionCount, msg.getExtensionCount().getValue().intValue());

        assertEquals(
                expectedNameLengthOfServerSigAlgsExtension,
                serverSigAlgsExtension.getNameLength().getValue().intValue());
        assertEquals(
                expectedNameOfServerSigAlgsExtension, serverSigAlgsExtension.getName().getValue());
        assertEquals(
                expectedValueLengthOfServerSigAlgsExtension,
                serverSigAlgsExtension
                        .getAcceptedPublicKeyAlgorithmsLength()
                        .getValue()
                        .intValue());
        assertEquals(
                expectedValueOfServerSigAlgsExtension,
                serverSigAlgsExtension.getAcceptedPublicKeyAlgorithms().getValue());

        assertEquals(
                expectedNameLengthOfDelayCompressionExtension,
                delayCompressionExtension.getNameLength().getValue().intValue());
        assertEquals(
                expectedNameOfDelayCompressionExtension,
                delayCompressionExtension.getName().getValue());
        assertEquals(
                expectedValueLengthOfDelayCompressionExtension,
                delayCompressionExtension.getCompressionMethodsLength().getValue().intValue());
        assertEquals(
                expectedCompressionMethodsClientToServerLength,
                delayCompressionExtension
                        .getCompressionMethodsClientToServerLength()
                        .getValue()
                        .intValue());
        assertEquals(
                expectedCompressionMethodsClientToServer,
                delayCompressionExtension.getCompressionMethodsClientToServer().getValue());
        assertEquals(
                expectedCompressionMethodsServerToClientLength,
                delayCompressionExtension
                        .getCompressionMethodsServerToClientLength()
                        .getValue()
                        .intValue());
        assertEquals(
                expectedCompressionMethodsServerToClient,
                delayCompressionExtension.getCompressionMethodsServerToClient().getValue());
    }
}
