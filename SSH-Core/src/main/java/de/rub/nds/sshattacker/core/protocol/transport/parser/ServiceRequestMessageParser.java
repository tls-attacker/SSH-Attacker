/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServiceRequestMessageParser extends MessageParser<ServiceRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServiceRequestMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ServiceRequestMessage createMessage() {
        return new ServiceRequestMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ServiceRequestMessage msg) {
        int length = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("serviceName Length: " + length);
        String serviceName = parseByteString(length);
        LOGGER.debug("serviceName: " + serviceName);
        msg.setServiceName(serviceName);
    }

}
