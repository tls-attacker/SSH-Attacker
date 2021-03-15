package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.UnimplementedMessage;

public class UnimplementedMessageSerializer extends MessageSerializer<UnimplementedMessage> {

    public UnimplementedMessageSerializer(UnimplementedMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        appendInt(msg.getSequenceNumber().getValue(), DataFormatConstants.INT32_SIZE);
        return getAlreadySerialized();
    }

}
