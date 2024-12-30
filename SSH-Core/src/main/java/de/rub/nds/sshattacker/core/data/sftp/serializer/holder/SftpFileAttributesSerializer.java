/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.SftpFileType;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpFileAttributesSerializer extends Serializer<SftpFileAttributes> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeFlags(SftpFileAttributes object, SerializerStream output) {
        Integer flags = object.getFlags().getValue();
        LOGGER.debug("Flags: {}", flags);
        output.appendInt(flags);
    }

    private static void serializeType(SftpFileAttributes object, SerializerStream output) {
        if (object.getType() != null) {
            Byte type = object.getType().getValue();
            LOGGER.debug("Type: {}", SftpFileType.getNameByType(type));
            output.appendByte(type);
        }
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

    private static void serializeOwnerGroup(SftpFileAttributes object, SerializerStream output) {
        if (object.getOwner() != null) {
            Integer ownerLength = object.getOwnerLength().getValue();
            LOGGER.debug("Owner length: {}", ownerLength);
            output.appendInt(ownerLength);
            String owner = object.getOwner().getValue();
            LOGGER.debug("Owner: {}", () -> backslashEscapeString(owner));
            output.appendString(owner, StandardCharsets.UTF_8);
        }
        if (object.getGroup() != null) {
            Integer groupLength = object.getGroupLength().getValue();
            LOGGER.debug("Group length: {}", groupLength);
            output.appendInt(groupLength);
            String group = object.getGroup().getValue();
            LOGGER.debug("Group: {}", () -> backslashEscapeString(group));
            output.appendString(group, StandardCharsets.UTF_8);
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

        // SFTP v4
        if (object.getAccessTimeLong() != null) {
            Long aTime = object.getAccessTimeLong().getValue();
            LOGGER.debug("ATime: {}", aTime);
            output.appendLong(aTime);
        }
        if (object.getAccessTimeNanoseconds() != null) {
            Integer aTimeNanoseconds = object.getAccessTimeNanoseconds().getValue();
            LOGGER.debug("ATime Nanoseconds: {}", aTimeNanoseconds);
            output.appendInt(aTimeNanoseconds);
        }
        if (object.getCreateTimeLong() != null) {
            Long cTime = object.getCreateTimeLong().getValue();
            LOGGER.debug("CTime: {}", cTime);
            output.appendLong(cTime);
        }
        if (object.getCreateTimeNanoseconds() != null) {
            Integer cTimeNanoseconds = object.getCreateTimeNanoseconds().getValue();
            LOGGER.debug("CTime Nanoseconds: {}", cTimeNanoseconds);
            output.appendInt(cTimeNanoseconds);
        }
        if (object.getModifyTimeLong() != null) {
            Long mTime = object.getModifyTimeLong().getValue();
            LOGGER.debug("MTime: {}", mTime);
            output.appendLong(mTime);
        }
        if (object.getModifyTimeNanoseconds() != null) {
            Integer mTimeNanoseconds = object.getModifyTimeNanoseconds().getValue();
            LOGGER.debug("MTime Nanoseconds: {}", mTimeNanoseconds);
            output.appendInt(mTimeNanoseconds);
        }
    }

    private static void serializeAcl(SftpFileAttributes object, SerializerStream output) {
        if (object.getAclEntriesCount() != null) {
            Integer aclLength = object.getAclLength().getValue();
            LOGGER.debug("AclLength: {}", aclLength);
            output.appendInt(aclLength);

            Integer aclEntriesCount = object.getAclEntriesCount().getValue();
            LOGGER.debug("AclEntriesCount: {}", aclEntriesCount);
            output.appendInt(aclEntriesCount);

            object.getAclEntries().forEach(aclEntry -> output.appendBytes(aclEntry.serialize()));
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
        serializeType(object, output);
        serializeSize(object, output);
        serializeUIdGId(object, output);
        serializeOwnerGroup(object, output);
        serializePermissions(object, output);
        serializeTimes(object, output);
        serializeAcl(object, output);
        serializeExtendedAttributes(object, output);
    }
}
