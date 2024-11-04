/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.attribute;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpAclEntry;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpAclEntrySerializer extends Serializer<SftpAclEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpAclEntry aclEntry;

    public SftpAclEntrySerializer(SftpAclEntry aclEntry) {
        super();
        this.aclEntry = aclEntry;
    }

    private void serializeType() {
        Integer type = aclEntry.getType().getValue();
        LOGGER.debug("Type: {}", type);
        appendInt(type, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeFlags() {
        Integer flags = aclEntry.getFlags().getValue();
        LOGGER.debug("Flags: {}", flags);
        appendInt(flags, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeMask() {
        Integer mask = aclEntry.getMask().getValue();
        LOGGER.debug("Mask: {}", mask);
        appendInt(mask, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeWho() {
        Integer whoLength = aclEntry.getWhoLength().getValue();
        LOGGER.debug("Who length: {}", whoLength);
        appendInt(whoLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String who = aclEntry.getWho().getValue();
        LOGGER.debug("Who: {}", () -> backslashEscapeString(who));
        appendString(who, StandardCharsets.UTF_8);
    }

    @Override
    protected final void serializeBytes() {
        serializeType();
        serializeFlags();
        serializeMask();
        serializeWho();
    }
}
