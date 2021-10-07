/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.connection.message.RequestFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.RequestFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.RequestFailureMessageSerializer;
import org.junit.jupiter.api.Test;

public class CyclicRequestFailureMessageTest {
    /** Cyclic test for parsing and serializing of RequestFailureMessage */
    @Test
    public void testCyclic() {
        byte[] bytes = new byte[] {82};
        RequestFailureMessage message = new RequestFailureMessageParser(0, bytes).parse();
        assertArrayEquals(bytes, new RequestFailureMessageSerializer(message).serialize());
    }
}
