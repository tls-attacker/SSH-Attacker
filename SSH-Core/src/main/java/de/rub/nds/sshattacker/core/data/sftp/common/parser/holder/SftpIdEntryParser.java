/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.holder;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpIdEntry;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpIdEntryParser extends Parser<SftpIdEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpIdEntry idEntry = new SftpIdEntry();

    public SftpIdEntryParser(byte[] array) {
        super(array);
    }

    public SftpIdEntryParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseId() {
        int id = parseIntField();
        idEntry.setId(id);
        LOGGER.debug("Id: {}", id);
    }

    @Override
    public final SftpIdEntry parse() {
        parseId();
        return idEntry;
    }
}
