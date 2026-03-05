/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpAclEntry;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpAclEntryParser extends Parser<SftpAclEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpAclEntry aclEntry = new SftpAclEntry();

    public SftpAclEntryParser(byte[] array) {
        super(array);
    }

    public SftpAclEntryParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseType() {
        int type = parseIntField();
        aclEntry.setType(type);
        LOGGER.debug("Type: {}", type);
    }

    private void parseFlags() {
        int flags = parseIntField();
        aclEntry.setFlags(flags);
        LOGGER.debug("Flags: {}", flags);
    }

    private void parseMask() {
        int mask = parseIntField();
        aclEntry.setMask(mask);
        LOGGER.debug("Mask: {}", mask);
    }

    private void parseWho() {
        int whoLength = parseIntField();
        aclEntry.setWhoLength(whoLength);
        LOGGER.debug("Who length: {}", whoLength);
        String who = parseByteString(whoLength, StandardCharsets.UTF_8);
        aclEntry.setWho(who);
        LOGGER.debug("Who: {}", () -> backslashEscapeString(who));
    }

    @Override
    public final SftpAclEntry parse() {
        parseType();
        parseFlags();
        parseMask();
        parseWho();
        return aclEntry;
    }
}
