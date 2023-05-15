/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestFailureMessage;

import org.junit.jupiter.api.Test;

public class GlobalRequestFailureMessageSerializerTest {
    /** Test of GlobalRequestFailureMessageSerializer::serialize method */
    @Test
    public void testSerialize() {
        GlobalRequestFailureMessage msg = new GlobalRequestFailureMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_REQUEST_FAILURE);
        assertArrayEquals(
                new byte[] {82}, new GlobalRequestFailureMessageSerializer(msg).serialize());
    }
}
