package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.DebugMessage;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DebugMessageParserTest {
    /**
     * Provides a stream of test vectors for the DebugMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(ArrayConverter.hexStringToByteArray("040000000005446562756700000002454E"), false,
                "Debug", "EN"), Arguments.of(ArrayConverter.hexStringToByteArray("040100000005446562756700000002454E"),
                true, "Debug", "EN"), Arguments.of(
                ArrayConverter.hexStringToByteArray("040100000005446562756700000000"), true, "Debug", ""));
    }

    /**
     * Test of DebugMessageParser::parse method
     *
     * @param providedBytes
     *            Bytes to parse
     * @param expectedAlwaysDisplay
     *            Expected value for the always display flag
     * @param expectedMessage
     *            Expected debug message
     * @param expectedLanguageTag
     *            Expected language tag
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedBytes, boolean expectedAlwaysDisplay, String expectedMessage,
            String expectedLanguageTag) {
        DebugMessageParser parser = new DebugMessageParser(0, providedBytes);
        DebugMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_DEBUG.id, msg.getMessageID().getValue());
        assertEquals(expectedAlwaysDisplay, msg.getAlwaysDisplay().getValue());
        assertEquals(expectedMessage, msg.getMessage().getValue());
        assertEquals(expectedLanguageTag, msg.getLanguageTag().getValue());
    }
}
