/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.parser.ServiceAcceptMessageParserTest;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.ServiceAcceptMessageSerializer;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ServiceAcceptMessageSerializerTest {
    /**
     * Provides a stream of test vectors for the ServiceAcceptMessageSerializer class
     *
     * @return A stream of test vectors to feed the testSerialize unit test
     */
    public static Stream<Arguments> provideTestVectors() {
        return ServiceAcceptMessageParserTest.provideTestVectors();
    }

    /**
     * Test of ServiceAcceptMessageSerializer::serialize method
     *
     * @param expectedBytes Expected output bytes of the serialize() call
     * @param providedServiceType Requested service type
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, ServiceType providedServiceType) {
        ServiceAcceptMessage msg = new ServiceAcceptMessage();
        msg.setServiceName(providedServiceType.toString(), true);
        ServiceAcceptMessageSerializer serializer = new ServiceAcceptMessageSerializer(msg);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
