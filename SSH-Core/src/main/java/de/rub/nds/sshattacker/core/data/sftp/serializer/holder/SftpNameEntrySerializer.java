/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpNameEntrySerializer extends Serializer<SftpNameEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeName(SftpNameEntry object, SerializerStream output) {
        Integer nameLength = object.getNameLength().getValue();
        LOGGER.debug("Name length: {}", nameLength);
        output.appendInt(nameLength);
        String name = object.getName().getValue();
        LOGGER.debug("Name: {}", () -> backslashEscapeString(name));
        output.appendString(name, StandardCharsets.UTF_8);
    }

    @Override
    protected final void serializeBytes(SftpNameEntry object, SerializerStream output) {
        serializeName(object, output);
    }
}
