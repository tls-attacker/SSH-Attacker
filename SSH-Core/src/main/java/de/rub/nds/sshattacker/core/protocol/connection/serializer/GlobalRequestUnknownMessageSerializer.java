/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestUnknownMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestUnknownMessageSerializer
        extends GlobalRequestMessageSerializer<GlobalRequestUnknownMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestUnknownMessageSerializer(GlobalRequestUnknownMessage message) {
        super(message);
    }

    public void serializeBreakLength() {
        LOGGER.debug(
                "Type specific data: {}",
                ArrayConverter.bytesToHexString(message.getTypeSpecificData().getValue()));
        appendBytes(message.getTypeSpecificData().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeBreakLength();
    }
}
