/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpNameEntryParser extends Parser<SftpNameEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpNameEntry nameEntry = new SftpNameEntry();

    public SftpNameEntryParser(byte[] array) {
        super(array);
    }

    public SftpNameEntryParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseName() {
        int nameLength = parseIntField();
        nameEntry.setNameLength(nameLength);
        LOGGER.debug("Name length: {}", nameLength);
        String name = parseByteString(nameLength, StandardCharsets.UTF_8);
        nameEntry.setName(name);
        LOGGER.debug("Name: {}", () -> backslashEscapeString(name));
    }

    @Override
    public final SftpNameEntry parse() {
        parseName();
        return nameEntry;
    }
}
