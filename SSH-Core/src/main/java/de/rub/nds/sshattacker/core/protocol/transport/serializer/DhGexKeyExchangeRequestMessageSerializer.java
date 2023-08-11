/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeRequestMessageSerializer
        extends SshMessageSerializer<DhGexKeyExchangeRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeRequestMessageSerializer(DhGexKeyExchangeRequestMessage message) {
        super(message);
    }

    private void serializeMinimalGroupSize() {
        LOGGER.debug("Minimal group size: " + message.getMinimalGroupSize().getValue());
        appendInt(message.getMinimalGroupSize().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializePreferredGroupSize() {
        LOGGER.debug("Preferred group size: " + message.getPreferredGroupSize().getValue());
        appendInt(message.getPreferredGroupSize().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeMaximalGroupSize() {
        LOGGER.debug("Maximal group size: " + message.getMaximalGroupSize().getValue());
        appendInt(message.getMaximalGroupSize().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeMinimalGroupSize();
        serializePreferredGroupSize();
        serializeMaximalGroupSize();
    }
}
