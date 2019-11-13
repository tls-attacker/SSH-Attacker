package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.UserAuthBannerMessage;

public class UserAuthBannerMessageSerializer extends MessageSerializer<UserAuthBannerMessage> {

    public UserAuthBannerMessageSerializer(UserAuthBannerMessage msg) {
        super(msg);
    }

    private void serializeMessageLength() {
        appendInt(msg.getMessageLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializeMessage() {
        appendString(msg.getMessage().getValue());
    }

    private void serializeLanguageTagLength() {
        appendInt(msg.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializeLanguageTag() {
        appendString(msg.getLanguageTag().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeMessageLength();
        serializeMessage();
        serializeLanguageTagLength();
        serializeLanguageTag();
        return getAlreadySerialized();
    }

}
