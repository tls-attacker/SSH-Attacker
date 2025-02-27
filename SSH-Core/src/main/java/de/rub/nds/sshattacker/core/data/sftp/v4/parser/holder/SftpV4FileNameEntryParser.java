/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.parser.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.v4.message.holder.SftpV4FileNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpV4FileNameEntryParser extends Parser<SftpV4FileNameEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpV4FileNameEntry nameEntry = new SftpV4FileNameEntry();

    public SftpV4FileNameEntryParser(byte[] array) {
        super(array);
    }

    public SftpV4FileNameEntryParser(byte[] array, int startPosition) {
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

    private void parseAttributes() {
        SftpV4FileAttributesParser attributesParser =
                new SftpV4FileAttributesParser(getArray(), getPointer());
        nameEntry.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    public final SftpV4FileNameEntry parse() {
        parseFilename();
        parseAttributes();
        return nameEntry;
    }
}
