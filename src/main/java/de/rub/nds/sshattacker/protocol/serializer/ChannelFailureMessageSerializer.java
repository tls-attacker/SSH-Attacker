package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.ChannelFailureMessage;

public class ChannelFailureMessageSerializer extends MessageSerializer<ChannelFailureMessage> {

    public ChannelFailureMessageSerializer(ChannelFailureMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        return new byte[0];
    }

}
