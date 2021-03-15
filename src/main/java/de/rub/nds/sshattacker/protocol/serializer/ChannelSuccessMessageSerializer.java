package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.ChannelSuccessMessage;

public class ChannelSuccessMessageSerializer extends MessageSerializer<ChannelSuccessMessage> {

    public ChannelSuccessMessageSerializer(ChannelSuccessMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        return new byte[0];
    }

}
