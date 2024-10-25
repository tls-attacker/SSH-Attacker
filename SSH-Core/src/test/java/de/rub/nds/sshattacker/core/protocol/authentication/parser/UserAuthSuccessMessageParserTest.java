/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.layer.data.Parser;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage;
import java.io.ByteArrayInputStream;
import org.junit.jupiter.api.Test;

public class UserAuthSuccessMessageParserTest {
    /** Test of UserAuthSuccessMessageParser::parse method */
    @Test
    public void testParse() {
        UserAuthSuccessMessage msg = new UserAuthSuccessMessage();
        Parser parser = new UserAuthSuccessMessageParser(new ByteArrayInputStream(new byte[] {52}));
        parser.parse(msg);
        assertEquals(
                MessageIdConstant.SSH_MSG_USERAUTH_SUCCESS.getId(), msg.getMessageId().getValue());
    }
}
