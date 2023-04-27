/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestTcpIpForwardMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class GlobalRequestTcpIpForwardMessageParser
        extends GlobalRequestMessageParser<GlobalRequestTcpIpForwardMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestTcpIpForwardMessageParser(byte[] array) {
        super(array);
    }

    public GlobalRequestTcpIpForwardMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseIPAddressToBind() {
        message.setIpAddressToBindLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("IP address to bind length: " + message.getIpAddressToBindLength().getValue());
        message.setIpAddressToBind(
                parseByteString(
                        message.getIpAddressToBindLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("IP address to bind: " + message.getIpAddressToBind().getValue());
    }

    private void parsePortToBind() {
        message.setPortToBind(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Port to bind: " + message.getPortToBind().getValue());
    }

    @Override
    public GlobalRequestTcpIpForwardMessage createMessage() {
        return new GlobalRequestTcpIpForwardMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseIPAddressToBind();
        parsePortToBind();
    }
}
