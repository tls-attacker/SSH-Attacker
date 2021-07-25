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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeOldRequestMessageSerializer extends MessageSerializer<DhGexKeyExchangeOldRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final DhGexKeyExchangeOldRequestMessage msg;

    public DhGexKeyExchangeOldRequestMessageSerializer(DhGexKeyExchangeOldRequestMessage msg) {
        super(msg);
        this.msg = msg;
    }

    private void serializePreferredGroupSize() {
        LOGGER.debug("Preferred group size: " + msg.getPreferredGroupSize().getValue());
        appendInt(msg.getPreferredGroupSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializePreferredGroupSize();
        return getAlreadySerialized();
    }
}
