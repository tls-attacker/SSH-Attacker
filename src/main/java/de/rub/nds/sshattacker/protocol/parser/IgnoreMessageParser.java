package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.IgnoreMessage;

public class IgnoreMessageParser extends MessageParser<IgnoreMessage> {

    public IgnoreMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public IgnoreMessage createMessage() {
        return new IgnoreMessage();
    }

    private void parseData(IgnoreMessage msg) {
        msg.setData(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    @Override
    protected void parseMessageSpecificPayload(IgnoreMessage msg) {
        parseData(msg);
    }

}
