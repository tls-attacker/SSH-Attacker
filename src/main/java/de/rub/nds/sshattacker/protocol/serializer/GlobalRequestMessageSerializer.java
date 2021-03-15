package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.GlobalRequestMessage;
import de.rub.nds.sshattacker.util.Converter;

public class GlobalRequestMessageSerializer extends MessageSerializer<GlobalRequestMessage> {

    public GlobalRequestMessageSerializer(GlobalRequestMessage msg) {
        super(msg);
    }

    private void serializeRequestName() {
        appendBytes(Converter.stringToLengthPrefixedString(msg.getRequestName().getValue()));
    }

    private void serializeWantReplay() {
        appendByte(msg.getWantReply().getValue());
    }

    private void serializePayload() {
        appendBytes(msg.getPayload().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRequestName();
        serializeWantReplay();
        serializePayload();
        return getAlreadySerialized();
    }

}
