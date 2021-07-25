/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.VersionExchangeMessageParser;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class VersionExchangeMessageParserTest {
    /**
     * Provides a stream of test vectors for the VersionExchangeMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(
                ArrayConverter.hexStringToByteArray("5353482d322e302d4f70656e5353485f372e380d0a"),
                "SSH-2.0-OpenSSH_7.8", ""), Arguments.of(
                ArrayConverter.hexStringToByteArray("5353482d322e302d6c69627373685f302e372e300d0a"),
                "SSH-2.0-libssh_0.7.0", ""));
    }

    /**
     * Test of VersionExchangeMessageParser::parse method
     * 
     * @param providedBytes
     *            Bytes to parse
     * @param expectedVersion
     *            Expected version string
     * @param expectedComment
     *            Expected comment string
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, String expectedVersion, String expectedComment) {
        VersionExchangeMessageParser parser = new VersionExchangeMessageParser(0, providedBytes);
        VersionExchangeMessage msg = parser.parse();

        assertEquals(expectedVersion, msg.getVersion().getValue());
        assertEquals(expectedComment, msg.getComment().getValue());
    }
}
