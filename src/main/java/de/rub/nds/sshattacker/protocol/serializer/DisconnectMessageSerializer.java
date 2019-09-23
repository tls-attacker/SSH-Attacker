package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.DisconnectMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageSerializer extends MessageSerializer<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageSerializer(DisconnectMessage msg) {
        super(msg);
    }

    private void serializeReasonCode() {
        LOGGER.debug("ReasonCode: " + msg.getReasonCode().getValue());
        appendInt(msg.getReasonCode().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeDescription() {
        int length = msg.getDescription().getValue().length();
        LOGGER.debug("DescriptionLength: " + length);
        appendInt(length, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Description: " + msg.getDescription().getValue());
        appendString(msg.getDescription().getValue());
    }

    private void serializeLanguageTag() {
        int length = msg.getDescription().getValue().length();
        appendInt(length, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("LanguageTag: " + msg.getLanguageTag().getValue());
        appendString(msg.getLanguageTag().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeReasonCode();
        serializeDescription();
        serializeLanguageTag();
        return getAlreadySerialized();
    }

}
