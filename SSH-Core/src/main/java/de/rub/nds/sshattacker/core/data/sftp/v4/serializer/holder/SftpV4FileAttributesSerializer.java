/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.serializer.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.SftpFileType;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.holder.SftpV4FileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpV4FileAttributesSerializer extends Serializer<SftpV4FileAttributes> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeFlags(SftpV4FileAttributes object, SerializerStream output) {
        Integer flags = object.getFlags().getValue();
        LOGGER.debug("Flags: {}", flags);
        output.appendInt(flags);
    }

    private static void serializeType(SftpV4FileAttributes object, SerializerStream output) {
        if (object.getType() != null) {
            Byte type = object.getType().getValue();
            LOGGER.debug("Type: {}", SftpFileType.getNameByType(type));
            output.appendByte(type);
        }
    }

    private static void serializeSize(SftpV4FileAttributes object, SerializerStream output) {
        if (object.getSize() != null) {
            Long size = object.getSize().getValue();
            LOGGER.debug("Size: {}", size);
            output.appendLong(size);
        }
    }

    private static void serializeOwnerGroup(SftpV4FileAttributes object, SerializerStream output) {
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

    private static void serializePermissions(SftpV4FileAttributes object, SerializerStream output) {
        if (object.getPermissions() != null) {
            Integer permissions = object.getPermissions().getValue();
            LOGGER.debug("Permissions: {}", permissions);
            output.appendInt(permissions);
        }
    }

    private static void serializeTimes(SftpV4FileAttributes object, SerializerStream output) {
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

    private static void serializeAcl(SftpV4FileAttributes object, SerializerStream output) {
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
            SftpV4FileAttributes object, SerializerStream output) {
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
    protected final void serializeBytes(SftpV4FileAttributes object, SerializerStream output) {
        serializeFlags(object, output);
        serializeType(object, output);
        serializeSize(object, output);
        serializeOwnerGroup(object, output);
        serializePermissions(object, output);
        serializeTimes(object, output);
        serializeAcl(object, output);
        serializeExtendedAttributes(object, output);
    }
}
