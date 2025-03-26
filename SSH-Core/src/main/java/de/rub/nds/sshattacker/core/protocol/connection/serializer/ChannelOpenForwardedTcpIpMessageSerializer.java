/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenForwardedTcpIpMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenForwardedTcpIpMessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenForwardedTcpIpMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenForwardedTcpIpMessageSerializer(ChannelOpenForwardedTcpIpMessage message) {
        super(message);
    }

    private void serializeConnectedAddress() {
        LOGGER.debug(
                "Connected address length: {}", message.getConnectedAddressLength().getValue());
        appendInt(
                message.getConnectedAddressLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Connected address: {}", message.getConnectedAddress().getValue());
        appendString(message.getConnectedAddress().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeConnectedPort() {
        LOGGER.debug("Connected port: {}", message.getConnectedPort().getValue());
        appendInt(message.getConnectedPort().getValue(), DataFormatConstants.UINT32_SIZE);
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
        serializeConnectedAddress();
        serializeConnectedPort();
        serializeOriginatorAddress();
        serializeOriginatorPort();
    }
}
