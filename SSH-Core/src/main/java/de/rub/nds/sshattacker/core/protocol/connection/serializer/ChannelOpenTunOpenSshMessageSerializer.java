/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenTunOpenSshMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenTunOpenSshMessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenTunOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeTunnelMode(
            ChannelOpenTunOpenSshMessage object, SerializerStream output) {
        LOGGER.debug("Tunnel mode: {}", object.getTunnelMode().getValue());
        output.appendInt(object.getTunnelMode().getValue());
    }

    private static void serializeRemoteUnitNumber(
            ChannelOpenTunOpenSshMessage object, SerializerStream output) {
        LOGGER.debug("Remote unit number: {}", object.getRemoteUnitNumber().getValue());
        output.appendInt(object.getRemoteUnitNumber().getValue());
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelOpenTunOpenSshMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeTunnelMode(object, output);
        serializeRemoteUnitNumber(object, output);
    }
}
