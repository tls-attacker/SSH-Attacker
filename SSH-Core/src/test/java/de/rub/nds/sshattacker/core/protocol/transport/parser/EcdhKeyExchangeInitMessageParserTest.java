/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import java.io.ByteArrayInputStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class EcdhKeyExchangeInitMessageParserTest {
    /**
     * Provides a stream of test vectors for the EcdhKeyExchangeInitMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "1E00000020c3579aa0b92395e888ed16a546587c5d8879f0f2f813b2bc68bab3325b9a6f0f"),
                        32,
                        ArrayConverter.hexStringToByteArray(
                                "c3579aa0b92395e888ed16a546587c5d8879f0f2f813b2bc68bab3325b9a6f0f")));
    }

    /**
     * Test of EcdhKeyExchangeInitMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedEphemeralPublicKeyLength Expected length of the public key
     * @param expectedEphemeralPublicKey Expected bytes of the public key
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes,
            int expectedEphemeralPublicKeyLength,
            byte[] expectedEphemeralPublicKey) {
        EcdhKeyExchangeInitMessageParser parser =
                new EcdhKeyExchangeInitMessageParser(new ByteArrayInputStream(providedBytes));
        EcdhKeyExchangeInitMessage msg = new EcdhKeyExchangeInitMessage();
        parser.parse(msg);

        assertEquals(
                MessageIdConstant.SSH_MSG_KEX_ECDH_INIT.getId(), msg.getMessageId().getValue());
        assertEquals(
                expectedEphemeralPublicKeyLength,
                msg.getEphemeralPublicKeyLength().getValue().intValue());
        assertArrayEquals(expectedEphemeralPublicKey, msg.getEphemeralPublicKey().getValue());
    }
}
