/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpAclEntry;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpAclEntrySerializer extends Serializer<SftpAclEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeType(SftpAclEntry object, SerializerStream output) {
        Integer type = object.getType().getValue();
        LOGGER.debug("Type: {}", type);
        output.appendInt(type);
    }

    private static void serializeFlags(SftpAclEntry object, SerializerStream output) {
        Integer flags = object.getFlags().getValue();
        LOGGER.debug("Flags: {}", flags);
        output.appendInt(flags);
    }

    private static void serializeMask(SftpAclEntry object, SerializerStream output) {
        Integer mask = object.getMask().getValue();
        LOGGER.debug("Mask: {}", mask);
        output.appendInt(mask);
    }

    private static void serializeWho(SftpAclEntry object, SerializerStream output) {
        Integer whoLength = object.getWhoLength().getValue();
        LOGGER.debug("Who length: {}", whoLength);
        output.appendInt(whoLength);
        String who = object.getWho().getValue();
        LOGGER.debug("Who: {}", () -> backslashEscapeString(who));
        output.appendString(who, StandardCharsets.UTF_8);
    }

    @Override
    protected final void serializeBytes(SftpAclEntry object, SerializerStream output) {
        serializeType(object, output);
        serializeFlags(object, output);
        serializeMask(object, output);
        serializeWho(object, output);
    }
}
