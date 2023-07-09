/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelEofMessage;
import java.io.InputStream;

public class ChannelEofMessageParser extends ChannelMessageParser<ChannelEofMessage> {

    /*
        public ChannelEofMessageParser(byte[] array) {
            super(array);
        }
        public ChannelEofMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public ChannelEofMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelEofMessage message) {
        parseProtocolMessageContents(message);
    }

    /*    @Override
    public ChannelEofMessage createMessage() {
        return new ChannelEofMessage();
    }*/
}
