/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenForwardedTcpIpMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenForwardedTcpIpMessageParser
        extends ChannelOpenMessageParser<ChannelOpenForwardedTcpIpMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenForwardedTcpIpMessageParser(byte[] array) {
        super(array);
    }

    public ChannelOpenForwardedTcpIpMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected ChannelOpenForwardedTcpIpMessage createMessage() {
        return new ChannelOpenForwardedTcpIpMessage();
    }

    public void parseConnectedHost() {
        message.setConnectedAddressLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Host to connect length: {}", message.getConnectedAddressLength().getValue());
        message.setConnectedAddress(
                parseByteString(
                        message.getConnectedAddressLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Host to connect: {}", message.getConnectedAddress().getValue());
    }

    public void parseConnectedPort() {
        message.setConnectedPort(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Port to connect: {}", message.getConnectedPort().getValue());
    }

    public void parseOriginatorAddress() {
        message.setOriginatorAddressLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Originator address length: {}", message.getOriginatorAddressLength().getValue());
        message.setOriginatorAddress(
                parseByteString(
                        message.getOriginatorAddressLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug("Originator address: {}", message.getOriginatorAddress().getValue());
    }

    public void parseOriginatorPort() {
        message.setOriginatorPort(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Originator port: {}", message.getOriginatorPort().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseConnectedHost();
        parseConnectedPort();
        parseOriginatorAddress();
        parseOriginatorPort();
    }
}
