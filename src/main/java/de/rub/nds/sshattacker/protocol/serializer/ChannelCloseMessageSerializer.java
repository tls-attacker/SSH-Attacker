package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelCloseMessage;

public class ChannelCloseMessageSerializer extends MessageSerializer<ChannelCloseMessage> {

    public ChannelCloseMessageSerializer(ChannelCloseMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
        return getAlreadySerialized();
    }

}
