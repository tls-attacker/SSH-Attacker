/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelTcpIpForwardMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestCancelTcpIpForwardMessageParser
        extends GlobalRequestMessageParser<GlobalRequestCancelTcpIpForwardMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestCancelTcpIpForwardMessageParser(byte[] array) {
        super(array);
    }

    public GlobalRequestCancelTcpIpForwardMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseIPAddressToBind() {
        int ipAddressToBindLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setIpAddressToBindLength(ipAddressToBindLength);
        LOGGER.debug("IP address to bind length: {}", ipAddressToBindLength);
        String ipAddressToBind = parseByteString(ipAddressToBindLength, StandardCharsets.US_ASCII);
        message.setIpAddressToBind(ipAddressToBind);
        LOGGER.debug("IP address to bind: {}", ipAddressToBind);
    }

    private void parsePortToBind() {
        int portToBind = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setPortToBind(portToBind);
        LOGGER.debug("Port to bind: {}", portToBind);
    }

    @Override
    public GlobalRequestCancelTcpIpForwardMessage createMessage() {
        return new GlobalRequestCancelTcpIpForwardMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseIPAddressToBind();
        parsePortToBind();
    }
}
