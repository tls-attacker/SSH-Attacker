package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelRequestMessage;

public class ChannelRequestMessageParser extends MessageParser<ChannelRequestMessage> {

    public ChannelRequestMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelRequestMessage createMessage() {
        return new ChannelRequestMessage();
    }

    private void parseRecipientChannel(ChannelRequestMessage msg) {
        msg.setRecipientChannel(parseIntField(DataFormatConstants.INT32_SIZE));
    }

    private void parseRequestType(ChannelRequestMessage msg) {
        int length = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        msg.setRequestType(parseByteString(length));
    }

    private void parseReplyWanted(ChannelRequestMessage msg) {
        msg.setReplyWanted(parseByteField(1));
    }

    private void parsePayload(ChannelRequestMessage msg) {
        int length = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        msg.setPayload(parseByteArrayField(length));
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelRequestMessage msg) {
        parseRecipientChannel(msg);
        parseRequestType(msg);
        parseReplyWanted(msg);
        parsePayload(msg);
    }

}
