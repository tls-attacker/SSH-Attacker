package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.protocol.message.RequestSuccessMessage;

public class RequestSuccessMessageParser extends MessageParser<RequestSuccessMessage> {

    public RequestSuccessMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public RequestSuccessMessage createMessage() {
        return new RequestSuccessMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(RequestSuccessMessage msg) {
        msg.setPayload(parseArrayOrTillEnd(-1));
    }

}
