package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.UserAuthFailureMessage;

public class UserAuthFailureMessageParser extends MessageParser<UserAuthFailureMessage> {

    public UserAuthFailureMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public UserAuthFailureMessage createMessage() {
        return new UserAuthFailureMessage();
    }

    private void parsePossibleAuthenticationMethods(UserAuthFailureMessage msg) {
        msg.setPossibleAuthenticationMethods(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    private void parsePartialSuccess(UserAuthFailureMessage msg) {
        msg.setPartialSuccess(parseByteField(1));
    }

    @Override
    protected void parseMessageSpecificPayload(UserAuthFailureMessage msg) {
        parsePossibleAuthenticationMethods(msg);
        parsePartialSuccess(msg);
    }

}
