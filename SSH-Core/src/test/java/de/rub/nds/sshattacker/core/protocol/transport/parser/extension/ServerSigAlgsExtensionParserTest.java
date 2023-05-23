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
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class ServerSigAlgsExtensionParserTest {
    /**
     * Provides a stream of test vectors for the ServerSigAlgsExtensionParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "0000000f7365727665722d7369672d616c6773000000897373682d656432353531392c65636473612d736861322d312e332e3133322e302e31302c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e697374703532312c7273612d736861322d3531322c7273612d736861322d3235362c7373682d7273612c7373682d647373"),
                        15,
                        "server-sig-algs",
                        137,
                        "ssh-ed25519,ecdsa-sha2-1.3.132.0.10,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss"),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "0000000f7365727665722d7369672d616c67730000000c666f6f2c6261722c74657374"),
                        15,
                        "server-sig-algs",
                        12,
                        "foo,bar,test"));
    }

    /**
     * Test of KeyExchangeInitMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedNameLength Expected length of 'server-sig-algs' string: 15
     * @param expectedName Expected string: 'server-sig-algs'
     * @param expectedValueLength Expected length of the value
     * @param expectedValue Expected value of server-sig-algs extension
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes,
            int expectedNameLength,
            String expectedName,
            int expectedValueLength,
            String expectedValue) {
        ServerSigAlgsExtensionParser parser = new ServerSigAlgsExtensionParser(providedBytes);
        ServerSigAlgsExtension extension = parser.parse();

        assertEquals(expectedNameLength, extension.getNameLength().getValue().intValue());
        assertEquals(expectedName, extension.getName().getValue());
        assertEquals(
                expectedValueLength,
                extension.getAcceptedPublicKeyAlgorithmsLength().getValue().intValue());
        assertEquals(expectedValue, extension.getAcceptedPublicKeyAlgorithms().getValue());
    }
}
