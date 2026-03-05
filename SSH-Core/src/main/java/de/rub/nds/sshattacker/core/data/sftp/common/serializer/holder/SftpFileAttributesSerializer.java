/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.holder;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpFileAttributesSerializer extends Serializer<SftpFileAttributes> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeFlags(SftpFileAttributes object, SerializerStream output) {
        Integer flags = object.getFlags().getValue();
        LOGGER.debug("Flags: {}", flags);
        output.appendInt(flags);
    }

    private static void serializeSize(SftpFileAttributes object, SerializerStream output) {
        if (object.getSize() != null) {
            Long size = object.getSize().getValue();
            LOGGER.debug("Size: {}", size);
            output.appendLong(size);
        }
    }

    private static void serializeUIdGId(SftpFileAttributes object, SerializerStream output) {
        if (object.getUserId() != null) {
            Integer uId = object.getUserId().getValue();
            LOGGER.debug("UId: {}", uId);
            output.appendInt(uId);
        }
        if (object.getGroupId() != null) {
            Integer gId = object.getGroupId().getValue();
            LOGGER.debug("GId: {}", gId);
            output.appendInt(gId);
        }
    }

    private static void serializePermissions(SftpFileAttributes object, SerializerStream output) {
        if (object.getPermissions() != null) {
            Integer permissions = object.getPermissions().getValue();
            LOGGER.debug("Permissions: {}", permissions);
            output.appendInt(permissions);
        }
    }

    private static void serializeTimes(SftpFileAttributes object, SerializerStream output) {
        // SFTP v3
        if (object.getAccessTime() != null) {
            Integer aTime = object.getAccessTime().getValue();
            LOGGER.debug("ATime: {}", aTime);
            output.appendInt(aTime);
        }
        if (object.getModifyTime() != null) {
            Integer mTime = object.getModifyTime().getValue();
            LOGGER.debug("MTime: {}", mTime);
            output.appendInt(mTime);
        }
    }

    private static void serializeExtendedAttributes(
            SftpFileAttributes object, SerializerStream output) {
        if (object.getExtendedCount() != null) {
            Integer extendedCount = object.getExtendedCount().getValue();
            LOGGER.debug("ExtendedCount: {}", extendedCount);
            output.appendInt(extendedCount);

            object.getExtendedAttributes()
                    .forEach(
                            extendedAttribute -> output.appendBytes(extendedAttribute.serialize()));
        }
    }

    @Override
    protected final void serializeBytes(SftpFileAttributes object, SerializerStream output) {
        serializeFlags(object, output);
        serializeSize(object, output);
        serializeUIdGId(object, output);
        serializePermissions(object, output);
        serializeTimes(object, output);
        serializeExtendedAttributes(object, output);
    }
}
