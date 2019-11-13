package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.UserAuthSuccessMessage;

public class UserAuthSuccessMessageSerializer extends MessageSerializer<UserAuthSuccessMessage> {

    public UserAuthSuccessMessageSerializer(UserAuthSuccessMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        return new byte[0];
    }

}
