package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.protocol.message.RequestFailureMessage;

public class RequestFailureMessageParser extends MessageParser<RequestFailureMessage> {

    public RequestFailureMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public RequestFailureMessage createMessage() {
        return new RequestFailureMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(RequestFailureMessage msg) {
    }

}
