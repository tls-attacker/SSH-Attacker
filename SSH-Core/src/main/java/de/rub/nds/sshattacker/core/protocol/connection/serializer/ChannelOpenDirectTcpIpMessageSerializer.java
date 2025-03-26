/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDirectTcpIpMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenDirectTcpIpMessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenDirectTcpIpMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenDirectTcpIpMessageSerializer(ChannelOpenDirectTcpIpMessage message) {
        super(message);
    }

    private void serializeHostToConnect() {
        LOGGER.debug("Host to connect length: {}", message.getHostToConnectLength().getValue());
        appendInt(
                message.getHostToConnectLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host to connect: {}", message.getHostToConnect().getValue());
        appendString(message.getHostToConnect().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializePortToConnect() {
        LOGGER.debug("Port to connect: {}", message.getPortToConnect().getValue());
        appendInt(message.getPortToConnect().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeOriginatorAddress() {
        LOGGER.debug(
                "Originator address length: {}", message.getOriginatorAddressLength().getValue());
        appendInt(
                message.getOriginatorAddressLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Originator address: {}", message.getOriginatorAddress().getValue());
        appendString(message.getOriginatorAddress().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeOriginatorPort() {
        LOGGER.debug("Originator port: {}", message.getOriginatorPort().getValue());
        appendInt(message.getOriginatorPort().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeHostToConnect();
        serializePortToConnect();
        serializeOriginatorAddress();
        serializeOriginatorPort();
    }
}
