/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeOldRequestMessageParser
        extends SshMessageParser<DhGexKeyExchangeOldRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeOldRequestMessageParser(byte[] array) {
        super(array);
    }

    public DhGexKeyExchangeOldRequestMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected DhGexKeyExchangeOldRequestMessage createMessage() {
        return new DhGexKeyExchangeOldRequestMessage();
    }

    private void parsePreferredGroupSize() {
        int preferredGroupSize = parseIntField();
        message.setPreferredGroupSize(preferredGroupSize);
        LOGGER.debug("Preferred group size: {} bits", preferredGroupSize);
    }

    @Override
    protected void parseMessageSpecificContents() {
        parsePreferredGroupSize();
    }
}
