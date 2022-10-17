/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import org.junit.jupiter.api.Test;

public class NewKeysMessageSerializerTest {
    /** Test of NewKeysMessageSerializer::serialize method */
    @Test
    public void testSerialize() {
        NewKeysMessage msg = new NewKeysMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_NEWKEYS);
        assertArrayEquals(new byte[] {21}, new NewKeysMessageSerializer(msg).serialize());
    }
}
