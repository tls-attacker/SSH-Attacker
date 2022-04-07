/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import org.junit.jupiter.api.Test;

public class NewKeysMessageParserTest {
    /** Test of NewKeysMessageParser::parse method */
    @Test
    public void testParse() {
        NewKeysMessage msg = new NewKeysMessageParser(new byte[] {21}).parse();
        assertEquals(MessageIdConstant.SSH_MSG_NEWKEYS.getId(), msg.getMessageId().getValue());
    }
}
