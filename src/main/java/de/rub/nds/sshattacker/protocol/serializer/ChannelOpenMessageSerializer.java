package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenMessageSerializer extends MessageSerializer<ChannelOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    
    public ChannelOpenMessageSerializer(ChannelOpenMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        LOGGER.debug("channel type: " + msg.getChannelType().getValue());
        appendBytes(Converter.stringToLengthPrefixedString(msg.getChannelType().getValue()));
        LOGGER.debug("senderChannel: " + msg.getSenderChannel().getValue());
        appendInt(msg.getSenderChannel().getValue(), DataFormatConstants.INT32_SIZE);
        LOGGER.debug("windowSize: " + msg.getWindowSize().getValue());
        appendInt(msg.getWindowSize().getValue(), DataFormatConstants.INT32_SIZE);
        LOGGER.debug("packetSize: " + msg.getPacketSize().getValue());
        appendInt(msg.getPacketSize().getValue(), DataFormatConstants.INT32_SIZE);
        return getAlreadySerialized();
    }

}
