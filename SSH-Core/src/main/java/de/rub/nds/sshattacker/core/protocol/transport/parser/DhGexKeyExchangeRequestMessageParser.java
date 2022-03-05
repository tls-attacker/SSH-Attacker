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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeRequestMessageParser
        extends SshMessageParser<DhGexKeyExchangeRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeRequestMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public DhGexKeyExchangeRequestMessage createMessage() {
        return new DhGexKeyExchangeRequestMessage();
    }

    public void parseMinimalGroupSize() {
        message.setMinimalGroupSize((parseIntField(DataFormatConstants.INT32_SIZE)));
        LOGGER.debug("Minimal group size: " + message.getMinimalGroupSize().getValue());
    }

    public void parsePreferedGroupSize() {
        message.setPreferredGroupSize(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Prefered group size: " + message.getPreferredGroupSize().getValue());
    }

    public void parseMaximalGroupSize() {
        message.setMaximalGroupSize(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Maximal group size" + message.getMaximalGroupSize().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseMinimalGroupSize();
        parsePreferedGroupSize();
        parseMaximalGroupSize();
    }
}
