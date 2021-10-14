/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
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
     * @param expectedPublicKeyLength Expected length of the public key
     * @param expectedPublicKey Expected bytes of the public key
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes, int expectedPublicKeyLength, byte[] expectedPublicKey) {
        EcdhKeyExchangeInitMessageParser parser =
                new EcdhKeyExchangeInitMessageParser(providedBytes, 0);
        EcdhKeyExchangeInitMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_KEX_ECDH_INIT.id, msg.getMessageID().getValue());
        assertEquals(expectedPublicKeyLength, msg.getPublicKeyLength().getValue().intValue());
        assertArrayEquals(expectedPublicKey, msg.getPublicKey().getValue());
    }
}
