/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestFailureMessage;

import org.junit.jupiter.api.Test;

public class GlobalRequestFailureMessageParserTest {
    /** Test of RequestFailureMessageParser::parse method */
    @Test
    public void testParse() {
        GlobalRequestFailureMessage msg =
                new GlobalRequestFailureMessageParser(new byte[] {82}).parse();
        assertEquals(
                MessageIdConstant.SSH_MSG_REQUEST_FAILURE.getId(), msg.getMessageId().getValue());
    }
}
