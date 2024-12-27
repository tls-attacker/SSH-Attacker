/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
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
        output.appendInt(flags, DataFormatConstants.UINT32_SIZE);
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
            output.appendLong(size, DataFormatConstants.UINT64_SIZE);
        }
    }

    private static void serializeUIdGId(SftpFileAttributes object, SerializerStream output) {
        if (object.getUserId() != null) {
            Integer uId = object.getUserId().getValue();
            LOGGER.debug("UId: {}", uId);
            output.appendInt(uId, DataFormatConstants.UINT32_SIZE);
        }
        if (object.getGroupId() != null) {
            Integer gId = object.getGroupId().getValue();
            LOGGER.debug("GId: {}", gId);
            output.appendInt(gId, DataFormatConstants.UINT32_SIZE);
        }
    }

    private static void serializeOwnerGroup(SftpFileAttributes object, SerializerStream output) {
        if (object.getOwner() != null) {
            Integer ownerLength = object.getOwnerLength().getValue();
            LOGGER.debug("Owner length: {}", ownerLength);
            output.appendInt(ownerLength, DataFormatConstants.STRING_SIZE_LENGTH);
            String owner = object.getOwner().getValue();
            LOGGER.debug("Owner: {}", () -> backslashEscapeString(owner));
            output.appendString(owner, StandardCharsets.UTF_8);
        }
        if (object.getGroup() != null) {
            Integer groupLength = object.getGroupLength().getValue();
            LOGGER.debug("Group length: {}", groupLength);
            output.appendInt(groupLength, DataFormatConstants.STRING_SIZE_LENGTH);
            String group = object.getGroup().getValue();
            LOGGER.debug("Group: {}", () -> backslashEscapeString(group));
            output.appendString(group, StandardCharsets.UTF_8);
        }
    }

    private static void serializePermissions(SftpFileAttributes object, SerializerStream output) {
        if (object.getPermissions() != null) {
            Integer permissions = object.getPermissions().getValue();
            LOGGER.debug("Permissions: {}", permissions);
            output.appendInt(permissions, DataFormatConstants.UINT32_SIZE);
        }
    }

    private static void serializeTimes(SftpFileAttributes object, SerializerStream output) {
        if (object.getAccessTime() != null) {
            Integer aTime = object.getAccessTime().getValue();
            LOGGER.debug("ATime: {}", aTime);
            output.appendInt(aTime, DataFormatConstants.UINT32_SIZE);
        }
        if (object.getCreateTime() != null) {
            Integer cTime = object.getCreateTime().getValue();
            LOGGER.debug("CTime: {}", cTime);
            output.appendInt(cTime, DataFormatConstants.UINT32_SIZE);
        }
        if (object.getModifyTime() != null) {
            Integer mTime = object.getModifyTime().getValue();
            LOGGER.debug("MTime: {}", mTime);
            output.appendInt(mTime, DataFormatConstants.UINT32_SIZE);
        }
    }

    private static void serializeAcl(SftpFileAttributes object, SerializerStream output) {
        if (object.getAclEntriesCount() != null) {
            Integer aclLength = object.getAclLength().getValue();
            LOGGER.debug("AclLength: {}", aclLength);
            output.appendInt(aclLength, DataFormatConstants.UINT32_SIZE);

            Integer aclEntriesCount = object.getAclEntriesCount().getValue();
            LOGGER.debug("AclEntriesCount: {}", aclEntriesCount);
            output.appendInt(aclEntriesCount, DataFormatConstants.UINT32_SIZE);

            object.getAclEntries().forEach(aclEntry -> output.appendBytes(aclEntry.serialize()));
        }
    }

    private static void serializeExtendedAttributes(
            SftpFileAttributes object, SerializerStream output) {
        if (object.getExtendedCount() != null) {
            Integer extendedCount = object.getExtendedCount().getValue();
            LOGGER.debug("ExtendedCount: {}", extendedCount);
            output.appendInt(extendedCount, DataFormatConstants.UINT32_SIZE);

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
