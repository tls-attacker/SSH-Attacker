package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.protocol.message.UserAuthSuccessMessage;

public class UserAuthSuccessMessageParser extends MessageParser<UserAuthSuccessMessage> {

    public UserAuthSuccessMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public UserAuthSuccessMessage createMessage() {
        return new UserAuthSuccessMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(UserAuthSuccessMessage msg) {
    }

}
