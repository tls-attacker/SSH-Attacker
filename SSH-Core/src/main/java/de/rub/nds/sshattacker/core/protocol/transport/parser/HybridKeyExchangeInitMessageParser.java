/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeInitMessageParser
        extends SshMessageParser<HybridKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeInitMessageParser(byte[] array) {
        super(array);
    }

    public HybridKeyExchangeInitMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parsePublicValues() {
        message.setPublicValuesLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Public values length: {}", message.getPublicValuesLength());
        message.setPublicValues(parseByteArrayField(message.getPublicValuesLength().getValue()));
        LOGGER.debug("Public values: {}", message.getPublicValues().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parsePublicValues();
    }

    @Override
    protected HybridKeyExchangeInitMessage createMessage() {
        return new HybridKeyExchangeInitMessage();
    }
}
