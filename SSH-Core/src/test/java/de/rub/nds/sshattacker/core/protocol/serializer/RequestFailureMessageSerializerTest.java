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

import de.rub.nds.sshattacker.core.protocol.connection.message.RequestFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.RequestFailureMessageSerializer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class RequestFailureMessageSerializerTest {
    /**
     * Test of KeyExchangeInitMessageSerializer::serialize method
     */
    @Test
    public void testSerialize() {
        RequestFailureMessage msg = new RequestFailureMessage();
        assertArrayEquals(new byte[] { 82 }, new RequestFailureMessageSerializer(msg).serialize());
    }
}
