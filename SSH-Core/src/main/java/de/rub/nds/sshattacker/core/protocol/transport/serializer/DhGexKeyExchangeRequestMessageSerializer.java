/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeRequestMessageSerializer extends MessageSerializer<DhGexKeyExchangeRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final DhGexKeyExchangeRequestMessage msg;

    public DhGexKeyExchangeRequestMessageSerializer(DhGexKeyExchangeRequestMessage msg) {
        super(msg);
        this.msg = msg;
    }

    private void serializeMinimalGroupSize() {
        LOGGER.debug("Minimal group size: " + msg.getMinimalGroupSize().getValue());
        appendInt(msg.getMinimalGroupSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializePreferredGroupSize() {
        LOGGER.debug("Preferred group size: " + msg.getPreferredGroupSize().getValue());
        appendInt(msg.getPreferredGroupSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeMaximalGroupSize() {
        LOGGER.debug("Maximal group size: " + msg.getMaximalGroupSize().getValue());
        appendInt(msg.getMaximalGroupSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeMinimalGroupSize();
        serializePreferredGroupSize();
        serializeMaximalGroupSize();
        return getAlreadySerialized();
    }
}
