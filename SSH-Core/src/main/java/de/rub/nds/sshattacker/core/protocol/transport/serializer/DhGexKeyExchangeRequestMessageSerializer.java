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
        Integer minimalGroupSize = message.getMinimalGroupSize().getValue();
        LOGGER.debug("Minimal group size: {}", minimalGroupSize);
        appendInt(minimalGroupSize, DataFormatConstants.UINT32_SIZE);
    }

    private void serializePreferredGroupSize() {
        Integer preferredGroupSize = message.getPreferredGroupSize().getValue();
        LOGGER.debug("Preferred group size: {}", preferredGroupSize);
        appendInt(preferredGroupSize, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeMaximalGroupSize() {
        Integer maximalGroupSize = message.getMaximalGroupSize().getValue();
        LOGGER.debug("Maximal group size: {}", maximalGroupSize);
        appendInt(maximalGroupSize, DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        serializeMinimalGroupSize();
        serializePreferredGroupSize();
        serializeMaximalGroupSize();
    }
}
