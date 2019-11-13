package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelEofMessage;

public class ChannelEofMessageSerializer extends MessageSerializer<ChannelEofMessage> {

    public ChannelEofMessageSerializer(ChannelEofMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
        return getAlreadySerialized();
    }

}
