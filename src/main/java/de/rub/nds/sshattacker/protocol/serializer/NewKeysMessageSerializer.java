package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;

public class NewKeysMessageSerializer extends BinaryPacketSerializer<NewKeysMessage> {

    public NewKeysMessageSerializer(NewKeysMessage msg) {
        super(msg);
    }
    
    @Override
    protected byte[] serializeMessageSpecificPayload() {
        return new byte[0];
    }
}
