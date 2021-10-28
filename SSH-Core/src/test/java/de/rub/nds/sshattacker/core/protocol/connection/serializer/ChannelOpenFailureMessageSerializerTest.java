/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenFailureMessageParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ChannelOpenFailureMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelOpenFailureMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelOpenFailureMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelCloseMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedRecipientChannel Recipient channel identifier
     * @param providedReasonCode Reason code
     * @param providedReason Reason string
     * @param providedLanguageTag Language tag string
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes,
            int providedRecipientChannel,
            int providedReasonCode,
            String providedReason,
            String providedLanguageTag) {
        ChannelOpenFailureMessage msg = new ChannelOpenFailureMessage();
        msg.setRecipientChannel(providedRecipientChannel);
        msg.setReasonCode(providedReasonCode);
        msg.setReason(providedReason, true);
        msg.setLanguageTag(providedLanguageTag, true);
        ChannelOpenFailureMessageSerializer serializer =
                new ChannelOpenFailureMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
