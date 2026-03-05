/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDirectTcpIpMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenDirectTcpIpMessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenDirectTcpIpMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeHostToConnect(
            ChannelOpenDirectTcpIpMessage object, SerializerStream output) {
        LOGGER.debug("Host to connect length: {}", object.getHostToConnectLength().getValue());
        output.appendInt(object.getHostToConnectLength().getValue());
        LOGGER.debug("Host to connect: {}", object.getHostToConnect().getValue());
        output.appendString(object.getHostToConnect().getValue(), StandardCharsets.US_ASCII);
    }

    private static void serializePortToConnect(
            ChannelOpenDirectTcpIpMessage object, SerializerStream output) {
        LOGGER.debug("Port to connect: {}", object.getPortToConnect().getValue());
        output.appendInt(object.getPortToConnect().getValue());
    }

    private static void serializeOriginatorAddress(
            ChannelOpenDirectTcpIpMessage object, SerializerStream output) {
        LOGGER.debug(
                "Originator address length: {}", object.getOriginatorAddressLength().getValue());
        output.appendInt(object.getOriginatorAddressLength().getValue());
        LOGGER.debug("Originator address: {}", object.getOriginatorAddress().getValue());
        output.appendString(object.getOriginatorAddress().getValue(), StandardCharsets.US_ASCII);
    }

    private static void serializeOriginatorPort(
            ChannelOpenDirectTcpIpMessage object, SerializerStream output) {
        LOGGER.debug("Originator port: {}", object.getOriginatorPort().getValue());
        output.appendInt(object.getOriginatorPort().getValue());
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelOpenDirectTcpIpMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeHostToConnect(object, output);
        serializePortToConnect(object, output);
        serializeOriginatorAddress(object, output);
        serializeOriginatorPort(object, output);
    }
}
