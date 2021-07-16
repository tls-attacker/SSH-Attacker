/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.cyclic;

import de.rub.nds.sshattacker.core.protocol.message.RequestFailureMessage;
import de.rub.nds.sshattacker.core.protocol.parser.RequestFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.serializer.RequestFailureMessageSerializer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class CyclicRequestFailureMessageTest {
    /**
     * Cyclic test for parsing and serializing of RequestFailureMessage
     */
    @Test
    public void testCyclic() {
        byte[] bytes = new byte[] { 82 };
        RequestFailureMessage message = new RequestFailureMessageParser(0, bytes).parse();
        assertArrayEquals(bytes, new RequestFailureMessageSerializer(message).serialize());
    }
}
