/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestTcpIpForwardMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
        int ipAddressToBindLength = parseIntField();
        message.setIpAddressToBindLength(ipAddressToBindLength);
        LOGGER.debug("IP address to bind length: {}", ipAddressToBindLength);
        String ipAddressToBind = parseByteString(ipAddressToBindLength, StandardCharsets.US_ASCII);
        message.setIpAddressToBind(ipAddressToBind);
        LOGGER.debug("IP address to bind: {}", ipAddressToBind);
    }

    private void parsePortToBind() {
        int portToBind = parseIntField();
        message.setPortToBind(portToBind);
        LOGGER.debug("Port to bind: {}", portToBind);
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
