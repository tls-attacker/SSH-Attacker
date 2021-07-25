/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelEofMessage;

public class ChannelEofMessageParser extends MessageParser<ChannelEofMessage> {

    public ChannelEofMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelEofMessage createMessage() {
        return new ChannelEofMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelEofMessage msg) {
        msg.setRecipientChannel(parseIntField(DataFormatConstants.INT32_SIZE));
    }

}
