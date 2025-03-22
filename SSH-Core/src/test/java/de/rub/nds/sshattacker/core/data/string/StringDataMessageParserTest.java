/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.string;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class StringDataMessageParserTest {
    /**
     * Provides a stream of test vectors for the StringDataMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(ArrayConverter.hexStringToByteArray("6C73202F"), "ls /"),
                Arguments.of(ArrayConverter.hexStringToByteArray("6C73202F726F6F74"), "ls /root"),
                Arguments.of(ArrayConverter.hexStringToByteArray("6364202E2E"), "cd .."));
    }

    /**
     * Test of StringDataMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedPayload Expected payload of the message
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, String expectedPayload) {
        StringDataMessageParser parser = new StringDataMessageParser(providedBytes);
        StringDataMessage msg = parser.parse();

        assertEquals(expectedPayload, msg.getData().getValue());
    }
}
