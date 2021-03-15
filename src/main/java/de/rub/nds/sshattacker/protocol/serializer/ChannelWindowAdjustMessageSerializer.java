package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelWindowAdjustMessage;

public class ChannelWindowAdjustMessageSerializer extends MessageSerializer<ChannelWindowAdjustMessage> {

    public ChannelWindowAdjustMessageSerializer(ChannelWindowAdjustMessage msg) {
        super(msg);
    }

    private void serializeRecipientChannel() {
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeBytesToAdd() {
        appendInt(msg.getBytesToAdd().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRecipientChannel();
        serializeBytesToAdd();
        return getAlreadySerialized();
    }

}
