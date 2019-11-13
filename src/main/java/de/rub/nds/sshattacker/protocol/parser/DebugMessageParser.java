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

    private void parseMessage(DebugMessage msg) {
        msg.setMessage(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    private void parseLanguageTag(DebugMessage msg) {
        msg.setLanguageTag(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    @Override
    protected void parseMessageSpecificPayload(DebugMessage msg) {
        parseAlwaysDisplay(msg);
        parseMessage(msg);
        parseLanguageTag(msg);
    }
}
