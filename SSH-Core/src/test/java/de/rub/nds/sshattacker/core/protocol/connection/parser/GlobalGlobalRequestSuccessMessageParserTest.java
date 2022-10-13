/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestSuccessMessage;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class GlobalGlobalRequestSuccessMessageParserTest {
    /**
     * Provides a stream of test vectors for the RequestSuccessMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(ArrayConverter.hexStringToByteArray("51"), new byte[0]));
    }

    /**
     * Test of RequestSuccessMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes) {
        GlobalRequestSuccessMessageParser parser =
                new GlobalRequestSuccessMessageParser(providedBytes);
        GlobalRequestSuccessMessage msg = parser.parse();

        assertEquals(
                MessageIdConstant.SSH_MSG_REQUEST_SUCCESS.getId(), msg.getMessageId().getValue());
    }
}
