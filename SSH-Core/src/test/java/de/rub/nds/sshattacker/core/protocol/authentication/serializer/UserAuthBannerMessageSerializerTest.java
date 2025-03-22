/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthBannerMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class UserAuthBannerMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the UserAuthBannerMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return UserAuthBannerMessageParserTest.provideTestVectors();
    }

    /**
     * Test of UserAuthBannerMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedMessage Message payload of the banner message
     * @param providedLanguageTag Language tag
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes, String providedMessage, String providedLanguageTag) {
        UserAuthBannerMessage msg = new UserAuthBannerMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_USERAUTH_BANNER);
        msg.setMessage(providedMessage, true);
        msg.setLanguageTag(providedLanguageTag, true);
        UserAuthBannerMessageSerializer serializer = new UserAuthBannerMessageSerializer();

        assertArrayEquals(expectedBytes, serializer.serialize(msg));
    }
}
