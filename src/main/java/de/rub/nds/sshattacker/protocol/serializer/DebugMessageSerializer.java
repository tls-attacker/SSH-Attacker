package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.DebugMessage;
import de.rub.nds.sshattacker.util.Converter;

public class DebugMessageSerializer extends MessageSerializer<DebugMessage> {

    public DebugMessageSerializer(DebugMessage msg) {
        super(msg);
    }

    private void serializeAlwaysDisplayed() {
        appendByte(msg.getAlwaysDisplay().getValue());
    }

    private void serializeMessage() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getMessage().getValue()));
    }

    private void serializeLanguageTag() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getLanguageTag().getValue()));
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeAlwaysDisplayed();
        serializeMessage();
        serializeLanguageTag();
        return getAlreadySerialized();
    }

}
