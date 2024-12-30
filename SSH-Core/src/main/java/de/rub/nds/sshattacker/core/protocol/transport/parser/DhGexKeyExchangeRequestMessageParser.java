/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeRequestMessageParser
        extends SshMessageParser<DhGexKeyExchangeRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeRequestMessageParser(byte[] array) {
        super(array);
    }

    public DhGexKeyExchangeRequestMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public DhGexKeyExchangeRequestMessage createMessage() {
        return new DhGexKeyExchangeRequestMessage();
    }

    private void parseMinimalGroupSize() {
        int minimalGroupSize = parseIntField();
        message.setMinimalGroupSize(minimalGroupSize);
        LOGGER.debug("Minimal DH group size: {} bits", minimalGroupSize);
    }

    private void parsePreferredGroupSize() {
        int preferredGroupSize = parseIntField();
        message.setPreferredGroupSize(preferredGroupSize);
        LOGGER.debug("Preferred DH group size: {} bits", preferredGroupSize);
    }

    private void parseMaximalGroupSize() {
        int maximalGroupSize = parseIntField();
        message.setMaximalGroupSize(maximalGroupSize);
        LOGGER.debug("Maximal DH group size: {} bits", maximalGroupSize);
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseMinimalGroupSize();
        parsePreferredGroupSize();
        parseMaximalGroupSize();
    }
}
