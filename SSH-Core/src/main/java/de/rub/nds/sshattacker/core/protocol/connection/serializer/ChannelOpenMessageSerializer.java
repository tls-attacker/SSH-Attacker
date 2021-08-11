/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenMessageSerializer extends MessageSerializer<ChannelOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenMessageSerializer(ChannelOpenMessage msg) {
        super(msg);
    }

    private void serializeChannelType() {
        LOGGER.debug("Channel type length: " + msg.getChannelTypeLength().getValue());
        appendInt(msg.getChannelTypeLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Channel type: " + msg.getChannelType().getValue());
        appendString(msg.getChannelType().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeSenderChannel() {
        LOGGER.debug("Sender channel: " + msg.getSenderChannel().getValue());
        appendInt(msg.getSenderChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeWindowSize() {
        LOGGER.debug("Initial window size: " + msg.getWindowSize().getValue());
        appendInt(msg.getWindowSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializePacketSize() {
        LOGGER.debug("Maximum packet size: " + msg.getWindowSize().getValue());
        appendInt(msg.getPacketSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        serializeChannelType();
        serializeSenderChannel();
        serializeWindowSize();
        serializePacketSize();
    }
}
