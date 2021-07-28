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

import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.core.protocol.parser.ServiceRequestMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.ServiceRequestMessageSerializer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class ServiceRequestMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ServiceRequestMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ServiceRequestMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ServiceRequestMessageSerializer::serialize method
     *
     * @param expectedBytes
     *            Expected output bytes of the serialize() call
     * @param providedServiceType
     *            Requested service type
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, ServiceType providedServiceType) {
        ServiceRequestMessage msg = new ServiceRequestMessage();
        msg.setServiceName(providedServiceType.toString(), true);
        ServiceRequestMessageSerializer serializer = new ServiceRequestMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
