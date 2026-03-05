/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenForwardedTcpIpMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenForwardedTcpIpMessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenForwardedTcpIpMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeConnectedAddress(
            ChannelOpenForwardedTcpIpMessage object, SerializerStream output) {
        LOGGER.debug("Connected address length: {}", object.getConnectedAddressLength().getValue());
        output.appendInt(object.getConnectedAddressLength().getValue());
        LOGGER.debug("Connected address: {}", object.getConnectedAddress().getValue());
        output.appendString(object.getConnectedAddress().getValue(), StandardCharsets.US_ASCII);
    }

    private static void serializeConnectedPort(
            ChannelOpenForwardedTcpIpMessage object, SerializerStream output) {
        LOGGER.debug("Connected port: {}", object.getConnectedPort().getValue());
        output.appendInt(object.getConnectedPort().getValue());
    }

    private static void serializeOriginatorAddress(
            ChannelOpenForwardedTcpIpMessage object, SerializerStream output) {
        LOGGER.debug(
                "Originator address length: {}", object.getOriginatorAddressLength().getValue());
        output.appendInt(object.getOriginatorAddressLength().getValue());
        LOGGER.debug("Originator address: {}", object.getOriginatorAddress().getValue());
        output.appendString(object.getOriginatorAddress().getValue(), StandardCharsets.US_ASCII);
    }

    private static void serializeOriginatorPort(
            ChannelOpenForwardedTcpIpMessage object, SerializerStream output) {
        LOGGER.debug("Originator port: {}", object.getOriginatorPort().getValue());
        output.appendInt(object.getOriginatorPort().getValue());
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelOpenForwardedTcpIpMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeConnectedAddress(object, output);
        serializeConnectedPort(object, output);
        serializeOriginatorAddress(object, output);
        serializeOriginatorPort(object, output);
    }
}
