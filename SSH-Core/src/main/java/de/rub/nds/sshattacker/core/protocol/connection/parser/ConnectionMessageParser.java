/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.ConnectionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConnectionMessageParser extends ProtocolMessageParser<ConnectionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     */
    public ConnectionMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ConnectionMessage message) {
        LOGGER.debug("Parsing ApplicationMessage");
        parseData(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    /**
     * Reads the next bytes as the Data and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseData(ConnectionMessage msg) {
        msg.setData(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("Data: {}", msg.getData().getValue());
    }
}
