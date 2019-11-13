package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.GlobalRequestMessage;

public class GlobalRequestMessageSerializer extends MessageSerializer<GlobalRequestMessage> {

    public GlobalRequestMessageSerializer(GlobalRequestMessage msg) {
        super(msg);
    }

    private void serializeRequestNameLength() {
        appendInt(msg.getRequestNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializeRequestName() {
        appendString(msg.getRequestName().getValue());
    }

    private void serializeWantReplay() {
        appendByte(msg.getWantReply().getValue());
    }

    private void serializePayload() {
        appendBytes(msg.getPayload().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRequestNameLength();
        serializeRequestName();
        serializeWantReplay();
        serializePayload();
        return getAlreadySerialized();
    }

}
