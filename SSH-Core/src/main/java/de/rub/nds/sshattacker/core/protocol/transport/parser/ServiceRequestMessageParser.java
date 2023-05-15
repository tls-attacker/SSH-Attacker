/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class ServiceRequestMessageParser extends SshMessageParser<ServiceRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServiceRequestMessageParser(byte[] array) {
        super(array);
    }

    public ServiceRequestMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseServiceName() {
        message.setServiceNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Service name length: {}", message.getServiceNameLength().getValue());
        message.setServiceName(
                parseByteString(
                        message.getServiceNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Service name: {}", backslashEscapeString(message.getServiceName().getValue()));
    }

    @Override
    public ServiceRequestMessage createMessage() {
        return new ServiceRequestMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseServiceName();
    }
}
