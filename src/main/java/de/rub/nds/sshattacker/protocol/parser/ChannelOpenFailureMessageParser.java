package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenFailureMessage;

public class ChannelOpenFailureMessageParser extends MessageParser<ChannelOpenFailureMessage> {

    public ChannelOpenFailureMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelOpenFailureMessage createMessage() {
        return new ChannelOpenFailureMessage();
    }

    private void parseRecipientChannel(ChannelOpenFailureMessage msg) {
        msg.setRecipientChannel(parseIntField(DataFormatConstants.INT32_SIZE));
    }

    private void parseReasonCode(ChannelOpenFailureMessage msg) {
        msg.setReasonCode(parseIntField(DataFormatConstants.INT32_SIZE));
    }

    private void parseReasonLength(ChannelOpenFailureMessage msg) {
        msg.setReasonLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
    }

    private void parseReason(ChannelOpenFailureMessage msg) {
        msg.setReason(parseByteString(msg.getReasonLength().getValue()));
    }

    private void parseLanguageTagLength(ChannelOpenFailureMessage msg) {
        msg.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
    }

    private void parseLanguageTag(ChannelOpenFailureMessage msg) {
        msg.setLanguageTag(parseByteString(msg.getLanguageTagLength().getValue()));
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelOpenFailureMessage msg) {
        parseRecipientChannel(msg);
        parseReasonCode(msg);
        parseReasonLength(msg);
        parseReason(msg);
        parseLanguageTagLength(msg);
        parseLanguageTag(msg);
    }

}
