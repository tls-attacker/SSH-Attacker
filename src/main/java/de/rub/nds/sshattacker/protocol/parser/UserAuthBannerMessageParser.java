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

    private void parseMessage(UserAuthBannerMessage msg) {
        msg.setMessage(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    private void parseLanguageTag(UserAuthBannerMessage msg) {
        msg.setLanguageTag(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    @Override
    protected void parseMessageSpecificPayload(UserAuthBannerMessage msg) {
        parseMessage(msg);
        parseLanguageTag(msg);
    }

}
