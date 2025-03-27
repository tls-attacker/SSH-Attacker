/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenTunOpenSshMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenTunOpenSshMessageParser
        extends ChannelOpenMessageParser<ChannelOpenTunOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenTunOpenSshMessageParser(byte[] array) {
        super(array);
    }

    public ChannelOpenTunOpenSshMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected ChannelOpenTunOpenSshMessage createMessage() {
        return new ChannelOpenTunOpenSshMessage();
    }

    public void parseTunnelMode() {
        message.setTunnelMode(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Tunnel mode: {}", message.getTunnelMode().getValue());
    }

    public void parseRemoteUnitNumber() {
        message.setRemoteUnitNumber(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Remote unit number: {}", message.getRemoteUnitNumber().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseTunnelMode();
        parseRemoteUnitNumber();
    }
}
