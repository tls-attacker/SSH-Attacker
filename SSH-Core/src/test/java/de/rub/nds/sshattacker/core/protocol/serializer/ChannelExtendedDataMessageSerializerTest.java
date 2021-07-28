/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.sshattacker.core.constants.ExtendedChannelDataType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelExtendedDataMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.parser.ChannelExtendedDataMessageParserTest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class ChannelExtendedDataMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ChannelExtendedDataMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ChannelExtendedDataMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ChannelExtendedDataMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedRecipientChannel
     *            Recipient channel identifier
     * @param providedDataType
     *            Data type
     * @param providedPayload
     *            Payload of the message
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, int providedRecipientChannel,
            ExtendedChannelDataType providedDataType, byte[] providedPayload) {
        ChannelExtendedDataMessage msg = new ChannelExtendedDataMessage();
        msg.setRecipientChannel(providedRecipientChannel);
        msg.setDataTypeCode(providedDataType.getDataTypeCode());
        msg.setData(providedPayload, true);
        ChannelExtendedDataMessageSerializer serializer = new ChannelExtendedDataMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
