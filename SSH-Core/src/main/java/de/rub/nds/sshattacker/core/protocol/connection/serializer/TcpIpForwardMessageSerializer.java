/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.connection.message.TcpIpForwardMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;

public abstract class TcpIpForwardMessageSerializer<T extends TcpIpForwardMessage<T>>
        extends GlobalRequestMessageSerializer<T> {
    
    private static final Logger LOGGER = LogManager.getLogger();

    public TcpIpForwardMessageSerializer(T message) {
        super(message);
    }

    private void serializeIPAddressToBind() {
        LOGGER.debug("IP address to bind length: " + message.getIPAddressToBindLength().getValue());
        appendInt(
                message.getIPAddressToBindLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("IP address to bind: " + message.getIPAddressToBind().getValue());
        appendString(message.getIPAddressToBind().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializePortToBind() {
        LOGGER.debug("Port to bind: " + message.getPortToBind().getValue());
        appendInt(
                message.getPortToBind().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeRequestName();
        serializeWantReply();
        serializeIPAddressToBind();
        serializePortToBind();
    }
}
