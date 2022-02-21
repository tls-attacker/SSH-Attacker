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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhKeyExchangeInitMessageParser extends SshMessageParser<DhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhKeyExchangeInitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected DhKeyExchangeInitMessage createMessage() {
        return new DhKeyExchangeInitMessage();
    }

    public void parsePublicKey() {
        message.setPublicKeyLength(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Public key length: " + message.getPublicKeyLength());
        message.setPublicKey(parseBigIntField(message.getPublicKeyLength().getValue()));
        LOGGER.debug("Public key: " + message.getPublicKey().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parsePublicKey();
    }
}
