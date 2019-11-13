package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelCloseMessage;

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
