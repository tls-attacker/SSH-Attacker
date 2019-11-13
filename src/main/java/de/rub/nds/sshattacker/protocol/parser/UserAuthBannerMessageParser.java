package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.UserAuthBannerMessage;

public class UserAuthBannerMessageParser extends MessageParser<UserAuthBannerMessage> {

    public UserAuthBannerMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public UserAuthBannerMessage createMessage() {
        return new UserAuthBannerMessage();
    }

    private void parseMessageLength(UserAuthBannerMessage msg) {
        msg.setMessageLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
    }

    private void parseMessage(UserAuthBannerMessage msg) {
        msg.setMessage(parseByteString(msg.getMessageLength().getValue()));
    }

    private void parseLanguageTagLength(UserAuthBannerMessage msg) {
        msg.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
    }

    private void parseLanguageTag(UserAuthBannerMessage msg) {
        msg.setLanguageTag(parseByteString(msg.getLanguageTagLength().getValue()));
    }

    @Override
    protected void parseMessageSpecificPayload(UserAuthBannerMessage msg) {
        parseMessageLength(msg);
        parseMessage(msg);
        parseLanguageTagLength(msg);
        parseLanguageTag(msg);
    }

}
