/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.response;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseNameEntrySerializer extends Serializer<SftpResponseNameEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpResponseNameEntry nameEntry;

    public SftpResponseNameEntrySerializer(SftpResponseNameEntry nameEntry) {
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
        Integer longNameLength = nameEntry.getLongNameLength().getValue();
        LOGGER.debug("LongName length: {}", longNameLength);
        appendInt(longNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String longName = nameEntry.getLongName().getValue();
        LOGGER.debug("LongName: {}", () -> backslashEscapeString(longName));
        appendString(longName, StandardCharsets.UTF_8);
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
