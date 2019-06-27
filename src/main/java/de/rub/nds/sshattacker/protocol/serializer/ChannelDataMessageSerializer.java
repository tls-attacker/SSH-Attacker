package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelDataMessage;
import de.rub.nds.sshattacker.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelDataMessageSerializer extends MessageSerializer<ChannelDataMessage>{

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelDataMessageSerializer(ChannelDataMessage msg) {
        super(msg);
    }
    
    @Override
    protected byte[] serializeMessageSpecificPayload() {
        LOGGER.debug("recipientChannel: " + msg.getRecipientChannel().getValue());
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
        LOGGER.debug("data: " + new String(msg.getData().getValue()));
        appendBytes(Converter.bytesToLenghPrefixedString(msg.getData().getValue()));
        return getAlreadySerialized();
    }

}
