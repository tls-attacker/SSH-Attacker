package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;

public class NewKeysMessageSerializer extends BinaryPacketSerializer<NewKeysMessage> {

    public NewKeysMessageSerializer(NewKeysMessage msg) {
        super(msg);
    }
    
    @Override
    protected byte[] serializeMessageSpecificPayload() {
        // does not have a message specific payload
        // specific part is only the messagetype
        return new byte[0];
    }
}
