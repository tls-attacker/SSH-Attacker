/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEndOfWriteMessage;

public class ChannelRequestEndOfWriteMessageParser
        extends ChannelRequestMessageParser<ChannelRequestEndOfWriteMessage> {
    public ChannelRequestEndOfWriteMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestEndOfWriteMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestEndOfWriteMessage createMessage() {
        return new ChannelRequestEndOfWriteMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
    }
}
