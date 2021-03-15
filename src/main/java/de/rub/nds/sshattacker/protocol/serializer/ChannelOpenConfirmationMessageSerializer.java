package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenConfirmationMessage;

public class ChannelOpenConfirmationMessageSerializer extends MessageSerializer<ChannelOpenConfirmationMessage> {

    public ChannelOpenConfirmationMessageSerializer(ChannelOpenConfirmationMessage msg) {
        super(msg);
    }

    private void serializeRecipientChannel() {
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeSenderChannel() {
        appendInt(msg.getSenderChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeWindowSize() {
        appendInt(msg.getWindowSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializePacketSize() {
        appendInt(msg.getPacketSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRecipientChannel();
        serializeSenderChannel();
        serializeWindowSize();
        serializePacketSize();
        return getAlreadySerialized();
    }

}
