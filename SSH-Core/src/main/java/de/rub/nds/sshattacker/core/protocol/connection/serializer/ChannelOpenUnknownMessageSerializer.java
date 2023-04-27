/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenUnknownMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenUnknownMessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenUnknownMessageSerializer(ChannelOpenUnknownMessage message) {
        super(message);
    }

    public void serializeTypeSpecificData() {
        LOGGER.debug(
                "Type specific data: "
                        + ArrayConverter.bytesToHexString(
                                message.getTypeSpecificData().getValue()));
        appendBytes(message.getTypeSpecificData().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeTypeSpecificData();
    }
}
