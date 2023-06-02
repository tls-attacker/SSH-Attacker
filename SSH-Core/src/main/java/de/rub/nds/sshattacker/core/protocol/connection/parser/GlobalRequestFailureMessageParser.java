/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestFailureMessage;
import java.io.InputStream;

public class GlobalRequestFailureMessageParser
        extends SshMessageParser<GlobalRequestFailureMessage> {

    /*
        public GlobalRequestFailureMessageParser(byte[] array) {
            super(array);
        }
        public GlobalRequestFailureMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public GlobalRequestFailureMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(GlobalRequestFailureMessage globalRequestFailureMessage) {
        parseMessageSpecificContents(globalRequestFailureMessage);
    }

    /*
        @Override
        public GlobalRequestFailureMessage createMessage() {
            return new GlobalRequestFailureMessage();
        }
    */

    @Override
    protected void parseMessageSpecificContents(GlobalRequestFailureMessage message) {}
}
