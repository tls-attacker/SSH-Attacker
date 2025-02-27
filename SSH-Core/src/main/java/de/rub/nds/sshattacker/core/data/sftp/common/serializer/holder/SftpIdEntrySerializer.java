/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.holder;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpIdEntry;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpIdEntrySerializer extends Serializer<SftpIdEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeId(SftpIdEntry object, SerializerStream output) {
        Integer id = object.getId().getValue();
        LOGGER.debug("Id: {}", id);
        output.appendInt(id);
    }

    @Override
    protected final void serializeBytes(SftpIdEntry object, SerializerStream output) {
        serializeId(object, output);
    }
}
