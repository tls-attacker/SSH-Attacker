/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.transport.parser.VersionExchangeMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.VersionExchangeMessageSerializer;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class VersionExchangeMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the VersionExchangeMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return VersionExchangeMessageParserTest.provideTestVectors();
    }

    /**
     * Test of VersionExchangeMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedVersion Version string
     * @param providedComment Comment string
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedBytes, String providedVersion, String providedComment) {
        VersionExchangeMessage msg = new VersionExchangeMessage();
        msg.setVersion(providedVersion);
        msg.setComment(providedComment);
        VersionExchangeMessageSerializer serializer = new VersionExchangeMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
