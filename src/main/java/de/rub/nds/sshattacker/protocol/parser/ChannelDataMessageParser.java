package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelDataMessageParser extends MessageParser<ChannelDataMessage>{
    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelDataMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelDataMessage createMessage() {
        return new ChannelDataMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelDataMessage msg) {
        msg.setRecipientChannel(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("recipientChannel: " + msg.getRecipientChannel());
        int length = parseIntField(DataFormatConstants.INT32_SIZE);
        LOGGER.debug("data length: " + length);
        msg.setData(parseByteArrayField(length));
        LOGGER.debug("data: " + new String(msg.getData().getValue()));
    }

}
