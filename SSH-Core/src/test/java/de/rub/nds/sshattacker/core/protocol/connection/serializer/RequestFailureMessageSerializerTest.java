/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.protocol.connection.message.RequestFailureMessage;
import org.junit.jupiter.api.Test;

public class RequestFailureMessageSerializerTest {
    /** Test of KeyExchangeInitMessageSerializer::serialize method */
    @Test
    public void testSerialize() {
        RequestFailureMessage msg = new RequestFailureMessage();
        assertArrayEquals(new byte[] {82}, new RequestFailureMessageSerializer(msg).serialize());
    }
}
