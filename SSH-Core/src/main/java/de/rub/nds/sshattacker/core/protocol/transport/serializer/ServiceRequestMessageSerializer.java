/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class ServiceRequestMessageSerializer extends SshMessageSerializer<ServiceRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServiceRequestMessageSerializer(ServiceRequestMessage message) {
        super(message);
    }

    private void serializeServiceName() {
        LOGGER.debug("Service name length: {}", message.getServiceNameLength().getValue());
        appendInt(message.getServiceNameLength().getValue(), DataFormatConstants.UINT32_SIZE);
        LOGGER.debug(
                "Service name: {}", backslashEscapeString(message.getServiceName().getValue()));
        appendString(message.getServiceName().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeServiceName();
    }
}
