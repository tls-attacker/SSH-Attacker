/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnimplementedMessageParser extends MessageParser<UnimplementedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnimplementedMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseSequenceNumber(UnimplementedMessage msg) {
        msg.setSequenceNumber(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Sequence number: " + msg.getSequenceNumber());
    }

    @Override
    protected void parseMessageSpecificPayload(UnimplementedMessage msg) {
        parseSequenceNumber(msg);
    }

    @Override
    public UnimplementedMessage createMessage() {
        return new UnimplementedMessage();
    }
}
