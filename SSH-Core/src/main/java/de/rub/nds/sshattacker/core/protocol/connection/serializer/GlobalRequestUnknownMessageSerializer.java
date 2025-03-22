/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestUnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestUnknownMessageSerializer
        extends GlobalRequestMessageSerializer<GlobalRequestUnknownMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeBreakLength(
            GlobalRequestUnknownMessage object, SerializerStream output) {
        byte[] typeSpecificData = object.getTypeSpecificData().getValue();
        LOGGER.debug(
                "Type specific data: {}", () -> ArrayConverter.bytesToHexString(typeSpecificData));
        output.appendBytes(typeSpecificData);
    }

    @Override
    protected void serializeMessageSpecificContents(
            GlobalRequestUnknownMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeBreakLength(object, output);
    }
}
