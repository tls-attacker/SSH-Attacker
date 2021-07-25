/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.RequestFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.RequestFailureMessageParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RequestFailureMessageParserTest {
    /**
     * Test of RequestFailureMessageParser::parse method
     */
    @Test
    public void testParse() {
        RequestFailureMessage msg = new RequestFailureMessageParser(0, new byte[] { 82 }).parse();
        assertEquals(MessageIDConstant.SSH_MSG_REQUEST_FAILURE.id, msg.getMessageID().getValue());
    }
}
