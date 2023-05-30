/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage;
import org.junit.jupiter.api.Test;

public class UserAuthSuccessMessageSerializerTest {
    /** Test of UserAuthSuccessMessageSerializer::serialize method */
    @Test
    public void testSerialize() {
        UserAuthSuccessMessage msg = new UserAuthSuccessMessage();
        msg.setMessageId(MessageIdConstant.SSH_MSG_USERAUTH_SUCCESS);
        assertArrayEquals(new byte[] {52}, new UserAuthSuccessMessageSerializer(msg).serialize());
    }
}
