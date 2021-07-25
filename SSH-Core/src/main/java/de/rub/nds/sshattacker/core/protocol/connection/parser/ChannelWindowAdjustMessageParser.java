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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;

public class ChannelWindowAdjustMessageParser extends MessageParser<ChannelWindowAdjustMessage> {

    public ChannelWindowAdjustMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelWindowAdjustMessage createMessage() {
        return new ChannelWindowAdjustMessage();
    }

    private void parseRecipientChannel(ChannelWindowAdjustMessage msg) {
        msg.setRecipientChannel(parseIntField(DataFormatConstants.INT32_SIZE));
    }

    private void parseBytesToAdd(ChannelWindowAdjustMessage msg) {
        msg.setBytesToAdd(parseIntField(DataFormatConstants.INT32_SIZE));
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelWindowAdjustMessage msg) {
        parseRecipientChannel(msg);
        parseBytesToAdd(msg);
    }

}
