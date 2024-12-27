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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpFileNameEntrySerializer extends Serializer<SftpFileNameEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeFilename(SftpFileNameEntry object, SerializerStream output) {
        Integer filenameLength = object.getFilenameLength().getValue();
        LOGGER.debug("Filename length: {}", filenameLength);
        output.appendInt(filenameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String filename = object.getFilename().getValue();
        LOGGER.debug("Filename: {}", () -> backslashEscapeString(filename));
        output.appendString(filename, StandardCharsets.UTF_8);
    }

    private static void serializeLongName(SftpFileNameEntry object, SerializerStream output) {
        if (object.getLongName() != null) {
            Integer longNameLength = object.getLongNameLength().getValue();
            LOGGER.debug("LongName length: {}", longNameLength);
            output.appendInt(longNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
            String longName = object.getLongName().getValue();
            LOGGER.debug("LongName: {}", () -> backslashEscapeString(longName));
            output.appendString(longName, StandardCharsets.UTF_8);
        }
    }

    private static void serializeAttributes(SftpFileNameEntry object, SerializerStream output) {
        output.appendBytes(object.getAttributes().serialize());
    }

    @Override
    protected final void serializeBytes(SftpFileNameEntry object, SerializerStream output) {
        serializeFilename(object, output);
        serializeLongName(object, output);
        serializeAttributes(object, output);
    }
}
