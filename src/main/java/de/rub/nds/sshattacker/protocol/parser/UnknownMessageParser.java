package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.protocol.message.UnknownMessage;

public class UnknownMessageParser extends MessageParser<UnknownMessage> {

    public UnknownMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public UnknownMessage createMessage() {
        return new UnknownMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(UnknownMessage msg) {
        msg.setPayload(parseArrayOrTillEnd(-1));
    }
}
