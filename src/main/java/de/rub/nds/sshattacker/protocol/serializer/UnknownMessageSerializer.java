package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.UnknownMessage;

public class UnknownMessageSerializer extends MessageSerializer<UnknownMessage>{

    
    private final UnknownMessage msg;
    
    public UnknownMessageSerializer(UnknownMessage msg) {
        super(msg);
        this.msg = msg;
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        return msg.getPayload().getValue();
    }
}
