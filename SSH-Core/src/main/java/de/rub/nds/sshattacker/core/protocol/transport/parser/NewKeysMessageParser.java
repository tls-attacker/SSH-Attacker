/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import java.io.InputStream;

public class NewKeysMessageParser extends SshMessageParser<NewKeysMessage> {

    /*
        public NewKeysMessageParser(byte[] array) {
            super(array);
        }
        public NewKeysMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public NewKeysMessageParser(InputStream stream) {
        super(stream);
    }

    /*
        @Override
        public NewKeysMessage createMessage() {
            return new NewKeysMessage();
        }
    */

    @Override
    protected void parseMessageSpecificContents(NewKeysMessage message) {
        // does nothing, only used to take the one byte out of the stream
        // parseByteString(1);
    }

    @Override
    public void parse(NewKeysMessage message) {
        parseProtocolMessageContents(message);
    }
}
