package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelExtendedDataMessage;
import de.rub.nds.sshattacker.util.Converter;

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

    private void serializeData() {
        appendBytes(Converter.stringToLengthPrefixedString(msg.getData().getValue()));
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRecipientChannel();
        serializeDataTypeCode();
        serializeData();
        return getAlreadySerialized();
    }

}
