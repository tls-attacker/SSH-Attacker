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

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.message.UserAuthSuccessMessage;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class UserAuthSuccessMessageSerializerTest {
    /**
     * Test of UserAuthSuccessMessageSerializer::serialize method
     */
    @Test
    public void testSerialize() {
        UserAuthSuccessMessage msg = new UserAuthSuccessMessage();
        msg.setMessageID(MessageIDConstant.SSH_MSG_USERAUTH_SUCCESS.id);
        assertArrayEquals(new byte[] { 52 }, new UserAuthSuccessMessageSerializer(msg).serialize());
    }
}
