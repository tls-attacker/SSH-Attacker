package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelWindowAdjustMessage;

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
