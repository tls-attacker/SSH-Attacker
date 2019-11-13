package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelExtendedDataMessage;

public class ChannelExtendedDataMessageParser extends MessageParser<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelExtendedDataMessage createMessage() {
        return new ChannelExtendedDataMessage();
    }

    private void parseRecipientChannel(ChannelExtendedDataMessage msg) {
        msg.setRecipientChannel(parseIntField(DataFormatConstants.INT32_SIZE));
    }

    private void parseDataTypeCode(ChannelExtendedDataMessage msg) {
        msg.setDataTypeCode(parseIntField(DataFormatConstants.INT32_SIZE));
    }

    private void parseDataLength(ChannelExtendedDataMessage msg) {
        msg.setDataLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
    }

    private void parseData(ChannelExtendedDataMessage msg) {
        msg.setData(parseByteString(msg.getDataLength().getValue()));
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelExtendedDataMessage msg) {
        parseRecipientChannel(msg);
        parseDataTypeCode(msg);
        parseDataLength(msg);
        parseData(msg);
    }

}
