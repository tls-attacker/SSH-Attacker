/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class ServiceAcceptMessageParserTest {
    /**
     * Provides a stream of test vectors for the ServiceAcceptMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("060000000C7373682D7573657261757468"),
                        ServiceType.SSH_USERAUTH),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "060000000E7373682D636F6E6E656374696F6E"),
                        ServiceType.SSH_CONNECTION));
    }

    /**
     * Test of ServiceAcceptMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedServiceType Expected service type
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, ServiceType expectedServiceType) {
        ServiceAcceptMessageParser parser = new ServiceAcceptMessageParser(providedBytes);
        ServiceAcceptMessage msg = parser.parse();

        assertEquals(
                MessageIdConstant.SSH_MSG_SERVICE_ACCEPT.getId(), msg.getMessageId().getValue());
        assertEquals(expectedServiceType.toString(), msg.getServiceName().getValue());
    }
}
