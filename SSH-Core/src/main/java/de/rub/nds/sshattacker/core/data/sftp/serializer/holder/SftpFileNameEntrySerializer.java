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
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpFileNameEntrySerializer extends Serializer<SftpFileNameEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpFileNameEntry nameEntry;

    public SftpFileNameEntrySerializer(SftpFileNameEntry nameEntry) {
        super();
        this.nameEntry = nameEntry;
    }

    private void serializeFilename() {
        Integer filenameLength = nameEntry.getFilenameLength().getValue();
        LOGGER.debug("Filename length: {}", filenameLength);
        appendInt(filenameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String filename = nameEntry.getFilename().getValue();
        LOGGER.debug("Filename: {}", () -> backslashEscapeString(filename));
        appendString(filename, StandardCharsets.UTF_8);
    }

    private void serializeLongName() {
        if (nameEntry.getLongName() != null) {
            Integer longNameLength = nameEntry.getLongNameLength().getValue();
            LOGGER.debug("LongName length: {}", longNameLength);
            appendInt(longNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
            String longName = nameEntry.getLongName().getValue();
            LOGGER.debug("LongName: {}", () -> backslashEscapeString(longName));
            appendString(longName, StandardCharsets.UTF_8);
        }
    }

    private void serializeAttributes() {
        appendBytes(nameEntry.getAttributes().getHandler(null).getSerializer().serialize());
    }

    @Override
    protected final void serializeBytes() {
        serializeFilename();
        serializeLongName();
        serializeAttributes();
    }
}
