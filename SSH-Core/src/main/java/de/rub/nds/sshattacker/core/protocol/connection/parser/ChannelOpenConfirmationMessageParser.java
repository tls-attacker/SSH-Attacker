/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessageParser
        extends ChannelMessageParser<ChannelOpenConfirmationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenConfirmationMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    @Override
    public ChannelOpenConfirmationMessage createMessage() {
        return new ChannelOpenConfirmationMessage();
    }

    private void parseSenderChannel(ChannelOpenConfirmationMessage msg) {
        msg.setSenderChannel(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Sender channel: " + msg.getSenderChannel().getValue());
    }

    private void parseWindowSize(ChannelOpenConfirmationMessage msg) {
        msg.setWindowSize(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Initial window size: " + msg.getWindowSize().getValue());
    }

    private void parsePacketSize(ChannelOpenConfirmationMessage msg) {
        msg.setPacketSize(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Maximum packet size: " + msg.getPacketSize().getValue());
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelOpenConfirmationMessage msg) {
        super.parseMessageSpecificPayload(msg);
        parseSenderChannel(msg);
        parseWindowSize(msg);
        parsePacketSize(msg);
    }
}
