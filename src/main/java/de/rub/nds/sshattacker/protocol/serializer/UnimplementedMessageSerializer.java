package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.UnimplementedMessage;

public class UnimplementedMessageSerializer extends MessageSerializer<UnimplementedMessage> {

    public UnimplementedMessageSerializer(UnimplementedMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        appendInt(msg.getSequenceNumber().getValue(), 0);
        return getAlreadySerialized();
    }

}
