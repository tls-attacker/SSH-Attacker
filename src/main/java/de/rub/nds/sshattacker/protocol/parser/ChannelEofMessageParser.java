package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelEofMessage;

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
