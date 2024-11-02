/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.response;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseNameEntry;
import de.rub.nds.sshattacker.core.data.sftp.parser.attribute.SftpFileAttributesParser;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseNameEntryParser extends Parser<SftpResponseNameEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpResponseNameEntry nameEntry = new SftpResponseNameEntry();

    public SftpResponseNameEntryParser(byte[] array) {
        super(array);
    }

    public SftpResponseNameEntryParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseFilename() {
        int filenameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        nameEntry.setFilenameLength(filenameLength);
        LOGGER.debug("Filename length: {}", filenameLength);
        String filename = parseByteString(filenameLength, StandardCharsets.UTF_8);
        nameEntry.setFilename(filename);
        LOGGER.debug("Filename: {}", () -> backslashEscapeString(filename));
    }

    private void parseLongName() {
        int longNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
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
    public final SftpResponseNameEntry parse() {
        parseFilename();
        parseLongName();
        parseAttributes();
        return nameEntry;
    }
}
