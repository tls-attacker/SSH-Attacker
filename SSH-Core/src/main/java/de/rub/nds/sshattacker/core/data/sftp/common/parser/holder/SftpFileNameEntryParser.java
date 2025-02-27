/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpFileNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpFileNameEntryParser extends Parser<SftpFileNameEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpFileNameEntry nameEntry = new SftpFileNameEntry();

    public SftpFileNameEntryParser(byte[] array) {
        super(array);
    }

    public SftpFileNameEntryParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseFilename() {
        int filenameLength = parseIntField();
        nameEntry.setFilenameLength(filenameLength);
        LOGGER.debug("Filename length: {}", filenameLength);
        String filename = parseByteString(filenameLength, StandardCharsets.UTF_8);
        nameEntry.setFilename(filename);
        LOGGER.debug("Filename: {}", () -> backslashEscapeString(filename));
    }

    private void parseLongName() {
        int longNameLength = parseIntField();
        nameEntry.setLongNameLength(longNameLength);
        LOGGER.debug("LongName length: {}", longNameLength);
        String longName = parseByteString(longNameLength, StandardCharsets.UTF_8);
        nameEntry.setLongName(longName);
        LOGGER.debug("LongName: {}", () -> backslashEscapeString(longName));
    }

    private void parseAttributes() {
        SftpFileAttributesParser attributesParser =
                new SftpFileAttributesParser(getArray(), getPointer());
        nameEntry.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    public final SftpFileNameEntry parse() {
        parseFilename();
        parseLongName();
        parseAttributes();
        return nameEntry;
    }
}
