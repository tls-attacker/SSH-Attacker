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
        LOGGER.debug("Filename length: {}", nameEntry.getFilenameLength().getValue());
        appendInt(nameEntry.getFilenameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Filename: {}", () -> backslashEscapeString(nameEntry.getFilename().getValue()));
        appendString(nameEntry.getFilename().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeLongName() {
        LOGGER.debug("LongName length: {}", nameEntry.getLongNameLength().getValue());
        appendInt(nameEntry.getLongNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "LongName: {}", () -> backslashEscapeString(nameEntry.getLongName().getValue()));
        appendString(nameEntry.getLongName().getValue(), StandardCharsets.UTF_8);
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
