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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServiceRequestMessageSerializer extends SshMessageSerializer<ServiceRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeServiceName(
            ServiceRequestMessage object, SerializerStream output) {
        Integer serviceNameLength = object.getServiceNameLength().getValue();
        LOGGER.debug("Service name length: {}", serviceNameLength);
        output.appendInt(serviceNameLength, DataFormatConstants.UINT32_SIZE);
        String serviceName = object.getServiceName().getValue();
        LOGGER.debug("Service name: {}", () -> backslashEscapeString(serviceName));
        output.appendString(serviceName, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ServiceRequestMessage object, SerializerStream output) {
        serializeServiceName(object, output);
    }
}
