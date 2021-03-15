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

    private void parseRequestName(GlobalRequestMessage msg) {
        msg.setRequestName(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    private void parseWantReply(GlobalRequestMessage msg) {
        msg.setWantReply(parseByteField(1));
    }

    private void parsePayload(GlobalRequestMessage msg) {
        msg.setPayload(parseArrayOrTillEnd(-1));
    }

    @Override
    protected void parseMessageSpecificPayload(GlobalRequestMessage msg) {
        parseRequestName(msg);
        parseWantReply(msg);
        parsePayload(msg);
    }

}
