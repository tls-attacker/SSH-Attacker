/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnimplementedMessageParser extends SshMessageParser<UnimplementedMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnimplementedMessageParser(InputStream stream) {
        super(stream);
    }

    private void parseSequenceNumber(UnimplementedMessage message) {
        message.setSequenceNumber(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Sequence number: {}", message.getSequenceNumber());
    }

    @Override
    protected void parseMessageSpecificContents(UnimplementedMessage message) {
        parseSequenceNumber(message);
    }

    @Override
    public void parse(UnimplementedMessage message) {
        parseProtocolMessageContents(message);
    }
}
