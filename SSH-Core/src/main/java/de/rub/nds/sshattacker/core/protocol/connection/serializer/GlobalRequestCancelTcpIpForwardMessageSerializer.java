/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelTcpIpForwardMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestCancelTcpIpForwardMessageSerializer
        extends GlobalRequestMessageSerializer<GlobalRequestCancelTcpIpForwardMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeIPAddressToBind(
            GlobalRequestCancelTcpIpForwardMessage object, SerializerStream output) {
        Integer ipAddressToBindLength = object.getIpAddressToBindLength().getValue();
        LOGGER.debug("IP address to bind length: {}", ipAddressToBindLength);
        output.appendInt(ipAddressToBindLength);
        String ipAddressToBind = object.getIpAddressToBind().getValue();
        LOGGER.debug("IP address to bind: {}", ipAddressToBind);
        output.appendString(ipAddressToBind, StandardCharsets.US_ASCII);
    }

    private static void serializePortToBind(
            GlobalRequestCancelTcpIpForwardMessage object, SerializerStream output) {
        Integer portToBind = object.getPortToBind().getValue();
        LOGGER.debug("Port to bind: {}", portToBind);
        output.appendInt(portToBind);
    }

    @Override
    protected void serializeMessageSpecificContents(
            GlobalRequestCancelTcpIpForwardMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeIPAddressToBind(object, output);
        serializePortToBind(object, output);
    }
}
