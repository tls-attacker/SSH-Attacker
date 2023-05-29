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

    /*
        public GlobalRequestNoMoreSessionsMessageParser(byte[] array) {
            super(array);
        }
        public GlobalRequestNoMoreSessionsMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public GlobalRequestNoMoreSessionsMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(GlobalRequestNoMoreSessionsMessage message) {
        parseMessageSpecificContents();
    }

    @Override
    public GlobalRequestNoMoreSessionsMessage createMessage() {
        return new GlobalRequestNoMoreSessionsMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
    }
}
