/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage;
import java.io.InputStream;

public class ChannelCloseMessageParser extends ChannelMessageParser<ChannelCloseMessage> {

    /*
        public ChannelCloseMessageParser(byte[] array) {
            super(array);
        }
        public ChannelCloseMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public ChannelCloseMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelCloseMessage message) {
        parseMessageSpecificContents(message);
    }

    /*    @Override
    public ChannelCloseMessage createMessage() {
        return new ChannelCloseMessage();
    }*/
}
