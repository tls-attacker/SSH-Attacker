/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.UnimplementedMessageParser;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class UnimplementedMessageParserTest {
    /**
     * Provides a stream of test vectors for the UnimplementedMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(ArrayConverter.hexStringToByteArray("0300000000"), 0),
                Arguments.of(ArrayConverter.hexStringToByteArray("0300000010"), 16),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("03FFFFFFFF"),
                        Integer.parseUnsignedInt("FFFFFFFF", 16)));
    }

    /**
     * Test of UnimplementedMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedSequenceNumber Expected sequence number
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, int expectedSequenceNumber) {
        UnimplementedMessageParser parser = new UnimplementedMessageParser(0, providedBytes);
        UnimplementedMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_UNIMPLEMENTED.id, msg.getMessageID().getValue());
        assertEquals(expectedSequenceNumber, msg.getSequenceNumber().getValue());
    }
}
