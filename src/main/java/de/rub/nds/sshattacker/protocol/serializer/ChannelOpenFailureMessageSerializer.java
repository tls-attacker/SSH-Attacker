package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenFailureMessage;

public class ChannelOpenFailureMessageSerializer extends MessageSerializer<ChannelOpenFailureMessage> {

    public ChannelOpenFailureMessageSerializer(ChannelOpenFailureMessage msg) {
        super(msg);
    }

    private void serializeRecipientChannel() {
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeReasonCode() {
        appendInt(msg.getReasonCode().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeReasonLength() {
        appendInt(msg.getReasonLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializeReason() {
        appendString(msg.getReason().getValue());
    }

    private void serializeLanguageTagLength() {
        appendInt(msg.getLanguageTagLength().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeLanguageTag() {
        appendString(msg.getLanguageTag().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRecipientChannel();
        serializeReasonCode();
        serializeReasonLength();
        serializeReason();
        serializeLanguageTagLength();
        serializeLanguageTag();
        return getAlreadySerialized();
    }

}
