package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.protocol.message.ChannelFailureMessage;

public class ChannelFailureMessageParser extends MessageParser<ChannelFailureMessage> {

    public ChannelFailureMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelFailureMessage createMessage() {
        return new ChannelFailureMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelFailureMessage msg) {

    }

}
