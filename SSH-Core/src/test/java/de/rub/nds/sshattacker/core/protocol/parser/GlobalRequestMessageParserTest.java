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
import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.GlobalRequestMessage;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class GlobalRequestMessageParserTest {
    /**
     * Provides a stream of test vectors for the GlobalRequestMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(ArrayConverter.hexStringToByteArray("500000000D74637069702D666F727761726400"),
                GlobalRequestType.TCPIP_FORWARD, (byte) 0x00, new byte[] {}), Arguments.of(
                ArrayConverter.hexStringToByteArray("500000001463616E63656C2D74637069702D666F72776172640100010203"),
                GlobalRequestType.CANCEL_TCPIP_FORWARD, (byte) 0x01, new byte[] { 0x00, 0x01, 0x02, 0x03 }), Arguments
                .of(ArrayConverter
                        .hexStringToByteArray("500000001C6E6F2D6D6F72652D73657373696F6E73406F70656E7373682E636F6D00"),
                        GlobalRequestType.NO_MORE_SESSIONS_OPENSSH_COM, (byte) 0x00, new byte[] {}));
    }

    /**
     * Test of GlobalRequestMessageParser::parse method
     *
     * @param providedBytes
     *            Bytes to parse
     * @param expectedRequestType
     *            Expected request type
     * @param expectedWantReply
     *            Expected value of the wantReply flag
     * @param expectedPayload
     *            Expected payload of the request
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, GlobalRequestType expectedRequestType, byte expectedWantReply,
            byte[] expectedPayload) {
        GlobalRequestMessageParser parser = new GlobalRequestMessageParser(0, providedBytes);
        GlobalRequestMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_GLOBAL_REQUEST.id, msg.getMessageID().getValue());
        assertEquals(expectedRequestType.toString(), msg.getRequestName().getValue());
        assertEquals(expectedWantReply, msg.getWantReply().getValue());
        assertArrayEquals(expectedPayload, msg.getPayload().getValue());
    }
}
