package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.DebugMessage;

public class DebugMessageParser extends MessageParser<DebugMessage> {

    public DebugMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public DebugMessage createMessage() {
        return new DebugMessage();
    }

    private void parseAlwaysDisplay(DebugMessage msg) {
        msg.setAlwaysDisplay(parseByteField(1));
    }

    private void parseMessageLength(DebugMessage msg) {
        msg.setMessageLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
    }

    private void parseMessage(DebugMessage msg) {
        msg.setMessage(parseByteString(msg.getMessageLength().getValue()));
    }

    private void parseLanguageTagLength(DebugMessage msg) {
        msg.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
    }

    private void parseLanguageTag(DebugMessage msg) {
        msg.setLanguageTag(parseByteString(msg.getLanguageTagLength().getValue()));
    }

    @Override
    protected void parseMessageSpecificPayload(DebugMessage msg) {
        parseAlwaysDisplay(msg);
        parseMessageLength(msg);
        parseMessage(msg);
        parseLanguageTagLength(msg);
        parseLanguageTag(msg);
    }
}
