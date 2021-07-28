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
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class ServiceAcceptMessageSerializer extends MessageSerializer<ServiceAcceptMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServiceAcceptMessageSerializer(ServiceAcceptMessage msg) {
        super(msg);
    }

    private void serializeServiceName() {
        LOGGER.debug("Service name length: " + msg.getServiceNameLength().getValue());
        appendInt(msg.getServiceNameLength().getValue(), DataFormatConstants.INT32_SIZE);
        LOGGER.debug("Service name: " + msg.getServiceName().getValue());
        appendString(msg.getServiceName().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        serializeServiceName();
    }
}
