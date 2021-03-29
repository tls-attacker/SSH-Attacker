/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ServiceAcceptMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServiceAcceptMessageParser extends MessageParser<ServiceAcceptMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServiceAcceptMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ServiceAcceptMessage createMessage() {
        return new ServiceAcceptMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ServiceAcceptMessage msg) {
        int length = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("serviceName Length: " + length);
        String serviceName = parseByteString(length);
        LOGGER.debug("serviceName: " + serviceName);
        msg.setServiceName(serviceName);
    }

}
