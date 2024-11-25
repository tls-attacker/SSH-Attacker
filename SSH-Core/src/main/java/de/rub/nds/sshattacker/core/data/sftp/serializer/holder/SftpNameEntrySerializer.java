/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpNameEntrySerializer extends Serializer<SftpNameEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpNameEntry nameEntry;

    public SftpNameEntrySerializer(SftpNameEntry nameEntry) {
        super();
        this.nameEntry = nameEntry;
    }

    private void serializeName() {
        Integer nameLength = nameEntry.getNameLength().getValue();
        LOGGER.debug("Name length: {}", nameLength);
        appendInt(nameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String name = nameEntry.getName().getValue();
        LOGGER.debug("Name: {}", () -> backslashEscapeString(name));
        appendString(name, StandardCharsets.UTF_8);
    }

    @Override
    protected final void serializeBytes() {
        serializeName();
    }
}
