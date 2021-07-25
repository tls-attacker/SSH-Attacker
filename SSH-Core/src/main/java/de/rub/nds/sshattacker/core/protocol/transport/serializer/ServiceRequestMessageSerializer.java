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

import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServiceRequestMessageSerializer extends MessageSerializer<ServiceRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ServiceRequestMessage msg;

    public ServiceRequestMessageSerializer(ServiceRequestMessage msg) {
        super(msg);
        this.msg = msg;
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        LOGGER.debug("serviceName: " + msg.getServiceName().getValue());
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getServiceName().getValue()));
        return getAlreadySerialized();
    }

}
