/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelTcpIpForwardMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestCancelTcpIpForwardMessageSerializer
        extends GlobalRequestMessageSerializer<GlobalRequestCancelTcpIpForwardMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestCancelTcpIpForwardMessageSerializer(
            GlobalRequestCancelTcpIpForwardMessage message) {
        super(message);
    }

    private void serializeIPAddressToBind() {
        Integer ipAddressToBindLength = message.getIpAddressToBindLength().getValue();
        LOGGER.debug("IP address to bind length: {}", ipAddressToBindLength);
        appendInt(ipAddressToBindLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("IP address to bind: {}", message.getIpAddressToBind().getValue());
        appendString(message.getIpAddressToBind().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializePortToBind() {
        Integer portToBind = message.getPortToBind().getValue();
        LOGGER.debug("Port to bind: {}", portToBind);
        appendInt(portToBind, DataFormatConstants.STRING_SIZE_LENGTH);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeIPAddressToBind();
        serializePortToBind();
    }
}
