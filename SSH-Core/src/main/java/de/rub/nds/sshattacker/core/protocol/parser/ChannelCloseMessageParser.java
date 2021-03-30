/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.message.ChannelCloseMessage;

public class ChannelCloseMessageParser extends MessageParser<ChannelCloseMessage> {

    public ChannelCloseMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelCloseMessage createMessage() {
        return new ChannelCloseMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelCloseMessage msg) {
        msg.setRecipientChannel(parseIntField(DataFormatConstants.INT32_SIZE));
    }

}
