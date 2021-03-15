package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.UnimplementedMessage;

public class UnimplementedMessageParser extends MessageParser<UnimplementedMessage> {

    public UnimplementedMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public UnimplementedMessage createMessage() {
        return new UnimplementedMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(UnimplementedMessage msg) {
        msg.setSequenceNumber(parseIntField(DataFormatConstants.INT32_SIZE));
    }

}
