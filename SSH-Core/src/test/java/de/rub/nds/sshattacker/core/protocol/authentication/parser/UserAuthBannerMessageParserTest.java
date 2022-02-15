/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class UserAuthBannerMessageParserTest {
    /**
     * Provides a stream of test vectors for the UserAuthBannerMessageParser class
     *
     * @return A stream of test vectors to feed the testParse unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(ArrayConverter.hexStringToByteArray("350000000000000000"), "", ""),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "35000000424265206177617265207468617420756E617574686F72697A656420636F6E6E656374696F6E20746F2074686973206D616368696E6520697320666F7262696464656E00000002656E"),
                        "Be aware that unauthorized connection to this machine is forbidden",
                        "en"),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "35000000334469657365204E616368726963687420736F6C6C2064656D2042656E75747A657220616E67657A656967742077657264656E21000000026465"),
                        "Diese Nachricht soll dem Benutzer angezeigt werden!",
                        "de"));
    }

    /**
     * Test of UserAuthBannerMessageParser::parse method
     *
     * @param providedBytes Bytes to parse
     * @param expectedMessage Expected message payload of the message
     * @param expectedLanguageTag Expected language tag
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedBytes, String expectedMessage, String expectedLanguageTag) {
        UserAuthBannerMessageParser parser = new UserAuthBannerMessageParser(providedBytes, 0);
        UserAuthBannerMessage msg = parser.parse();

        assertEquals(MessageIDConstant.SSH_MSG_USERAUTH_BANNER.id, msg.getMessageID().getValue());
        assertEquals(expectedMessage, msg.getMessage().getValue());
        assertEquals(expectedLanguageTag, msg.getLanguageTag().getValue());
    }
}
