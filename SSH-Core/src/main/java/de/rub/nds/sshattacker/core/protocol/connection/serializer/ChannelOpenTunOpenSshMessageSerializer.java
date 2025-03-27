/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenTunOpenSshMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenTunOpenSshMessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenTunOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenTunOpenSshMessageSerializer(ChannelOpenTunOpenSshMessage message) {
        super(message);
    }

    private void serializeTunnelMode() {
        LOGGER.debug("Tunnel mode: {}", message.getTunnelMode());
        appendInt(message.getTunnelMode().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeRemoteUnitNumber() {
        LOGGER.debug("Remote unit number: {}", message.getRemoteUnitNumber());
        appendInt(message.getRemoteUnitNumber().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeTunnelMode();
        serializeRemoteUnitNumber();
    }
}
