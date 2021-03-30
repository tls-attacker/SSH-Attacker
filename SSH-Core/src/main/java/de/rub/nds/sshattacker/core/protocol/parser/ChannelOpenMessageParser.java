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
import de.rub.nds.sshattacker.core.protocol.message.ChannelOpenMessage;

public class ChannelOpenMessageParser extends MessageParser<ChannelOpenMessage> {

    public ChannelOpenMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelOpenMessage createMessage() {
        return new ChannelOpenMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelOpenMessage msg) {
        parseChannelType(msg);
        parseSenderChannel(msg);
        parseWindowSize(msg);
        parsePacksetSize(msg);

    }

    public void parseChannelType(ChannelOpenMessage msg) {
        int length = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        msg.setChannelType(parseByteString(length));
    }

    public void parseSenderChannel(ChannelOpenMessage msg) {
        msg.setSenderChannel(parseIntField(DataFormatConstants.INT32_SIZE));
    }

    public void parseWindowSize(ChannelOpenMessage msg) {
        msg.setWindowSize(parseIntField(DataFormatConstants.INT32_SIZE));
    }

    public void parsePacksetSize(ChannelOpenMessage msg) {
        msg.setPacketSize(parseIntField(DataFormatConstants.INT32_SIZE));
    }
}
