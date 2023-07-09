/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestAuthAgentMessage;
import java.io.InputStream;

public class ChannelRequestAuthAgentMessageParser
        extends ChannelRequestMessageParser<ChannelRequestAuthAgentMessage> {

    /*
        public ChannelRequestAuthAgentMessageParser(byte[] array) {
            super(array);
        }
        public ChannelRequestAuthAgentMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public ChannelRequestAuthAgentMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelRequestAuthAgentMessage message) {
        parseProtocolMessageContents(message);
    }

    /*    @Override
    public ChannelRequestAuthAgentMessage createMessage() {
        return new ChannelRequestAuthAgentMessage();
    }*/
}
