/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.NewKeysMessageParser;
import org.junit.jupiter.api.Test;

public class NewKeysMessageParserTest {
    /** Test of NewKeysMessageParser::parse method */
    @Test
    public void testParse() {
        NewKeysMessage msg = new NewKeysMessageParser(0, new byte[] {21}).parse();
        assertEquals(MessageIDConstant.SSH_MSG_NEWKEYS.id, msg.getMessageID().getValue());
    }
}
