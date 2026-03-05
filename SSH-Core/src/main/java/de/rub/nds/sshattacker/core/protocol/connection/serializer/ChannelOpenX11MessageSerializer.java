/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenX11Message;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenX11MessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenX11Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeOriginatorAddress(
            ChannelOpenX11Message object, SerializerStream output) {
        LOGGER.debug(
                "Originator address length: {}", object.getOriginatorAddressLength().getValue());
        output.appendInt(object.getOriginatorAddressLength().getValue());
        LOGGER.debug("Originator address: {}", object.getOriginatorAddress().getValue());
        output.appendString(object.getOriginatorAddress().getValue(), StandardCharsets.US_ASCII);
    }

    private static void serializeOriginatorPort(
            ChannelOpenX11Message object, SerializerStream output) {
        LOGGER.debug("Originator port: {}", object.getOriginatorPort().getValue());
        output.appendInt(object.getOriginatorPort().getValue());
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelOpenX11Message object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeOriginatorAddress(object, output);
        serializeOriginatorPort(object, output);
    }
}
