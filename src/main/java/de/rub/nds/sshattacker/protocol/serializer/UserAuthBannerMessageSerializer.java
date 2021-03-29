package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.util.Converter;

public class UserAuthBannerMessageSerializer extends MessageSerializer<UserAuthBannerMessage> {

    public UserAuthBannerMessageSerializer(UserAuthBannerMessage msg) {
        super(msg);
    }

    private void serializeMessage() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getMessage().getValue()));
    }

    private void serializeLanguageTag() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getLanguageTag().getValue()));
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeMessage();
        serializeLanguageTag();
        return getAlreadySerialized();
    }

}
