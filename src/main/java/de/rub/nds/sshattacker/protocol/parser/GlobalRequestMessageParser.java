package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.GlobalRequestMessage;

public class GlobalRequestMessageParser extends MessageParser<GlobalRequestMessage> {

    public GlobalRequestMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public GlobalRequestMessage createMessage() {
        return new GlobalRequestMessage();
    }

    private void parseRequestNameLength(GlobalRequestMessage msg) {
        msg.setRequestNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
    }

    private void parseRequestName(GlobalRequestMessage msg) {
        msg.setRequestName(parseByteString(msg.getRequestNameLength().getValue()));
    }

    private void parseWantReply(GlobalRequestMessage msg) {
        msg.setWantReply(parseByteField(1));
    }

    private void parsePayload(GlobalRequestMessage msg) {
        msg.setPayload(parseArrayOrTillEnd(-1));
    }

    @Override
    protected void parseMessageSpecificPayload(GlobalRequestMessage msg) {
        parseRequestNameLength(msg);
        parseRequestName(msg);
        parseWantReply(msg);
        parsePayload(msg);
    }

}
