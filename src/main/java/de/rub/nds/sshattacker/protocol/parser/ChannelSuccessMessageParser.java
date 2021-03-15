package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.protocol.message.ChannelSuccessMessage;

public class ChannelSuccessMessageParser extends MessageParser<ChannelSuccessMessage> {

    public ChannelSuccessMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelSuccessMessage createMessage() {
        return new ChannelSuccessMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelSuccessMessage msg) {
    }

}
