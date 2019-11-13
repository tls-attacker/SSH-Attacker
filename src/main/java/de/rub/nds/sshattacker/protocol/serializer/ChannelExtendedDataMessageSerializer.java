package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelExtendedDataMessage;

public class ChannelExtendedDataMessageSerializer extends MessageSerializer<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessageSerializer(ChannelExtendedDataMessage msg) {
        super(msg);
    }

    private void serializeRecipientChannel() {
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeDataTypeCode() {
        appendInt(msg.getDataTypeCode().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeDataLength() {
        appendInt(msg.getDataLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializeData() {
        appendString(msg.getData().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRecipientChannel();
        serializeDataTypeCode();
        serializeDataLength();
        serializeData();
        return getAlreadySerialized();
    }

}
