package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenConfirmationMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessageParser extends MessageParser<ChannelOpenConfirmationMessage>{
    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenConfirmationMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelOpenConfirmationMessage createMessage() {
        return new ChannelOpenConfirmationMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelOpenConfirmationMessage msg) {
        msg.setRecipientChannel(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("recipientChannel: "+ msg.getRecipientChannel().getValue());
        msg.setSenderChannel(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("senderChannel: " + msg.getSenderChannel().getValue());
        msg.setWindowSize(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("windowSize: " + msg.getWindowSize().getValue());
        msg.setPacketSize(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("packetSize: " + msg.getPacketSize().getValue());
    }

    
}
