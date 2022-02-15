/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServiceAcceptMessageParser extends SshMessageParser<ServiceAcceptMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServiceAcceptMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseServiceType() {
        message.setServiceNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Service name length: " + message.getServiceNameLength());
        message.setServiceName(
                parseByteString(
                        message.getServiceNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Service name: " + message.getServiceName());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseServiceType();
    }

    @Override
    public ServiceAcceptMessage createMessage() {
        return new ServiceAcceptMessage();
    }
}
