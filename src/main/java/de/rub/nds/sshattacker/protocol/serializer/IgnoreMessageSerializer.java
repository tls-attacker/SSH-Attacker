package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.IgnoreMessage;

public class IgnoreMessageSerializer extends MessageSerializer<IgnoreMessage> {

    public IgnoreMessageSerializer(IgnoreMessage msg) {
        super(msg);
    }

    private void serializeDataLength() {
        appendInt(msg.getDataLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializeData() {
        appendString(msg.getData().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeDataLength();
        serializeData();
        return getAlreadySerialized();
    }

}
