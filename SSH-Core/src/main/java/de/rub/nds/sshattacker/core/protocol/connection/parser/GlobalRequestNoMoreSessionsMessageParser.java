/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestNoMoreSessionsMessage;
import java.io.InputStream;

public class GlobalRequestNoMoreSessionsMessageParser
        extends GlobalRequestMessageParser<GlobalRequestNoMoreSessionsMessage> {

    public GlobalRequestNoMoreSessionsMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(GlobalRequestNoMoreSessionsMessage message) {
        parseProtocolMessageContents(message);
    }

    @Override
    protected void parseMessageSpecificContents(GlobalRequestNoMoreSessionsMessage message) {
        super.parseMessageSpecificContents(message);
    }
}
