/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelWindowAdjustMessageParser
        extends ChannelMessageParser<ChannelWindowAdjustMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelWindowAdjustMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    @Override
    public ChannelWindowAdjustMessage createMessage() {
        return new ChannelWindowAdjustMessage();
    }

    private void parseBytesToAdd(ChannelWindowAdjustMessage msg) {
        msg.setBytesToAdd(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Bytes to add: " + msg.getBytesToAdd().getValue());
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelWindowAdjustMessage msg) {
        super.parseMessageSpecificPayload(msg);
        parseBytesToAdd(msg);
    }
}
