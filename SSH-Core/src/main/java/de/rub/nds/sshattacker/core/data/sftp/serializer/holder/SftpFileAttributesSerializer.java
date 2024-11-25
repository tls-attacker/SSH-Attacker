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
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpFileAttributesSerializer extends Serializer<SftpFileAttributes> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpFileAttributes attributes;

    public SftpFileAttributesSerializer(SftpFileAttributes attributes) {
        super();
        this.attributes = attributes;
    }

    private void serializeFlags() {
        Integer flags = attributes.getFlags().getValue();
        LOGGER.debug("Flags: {}", flags);
        appendInt(flags, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeType() {
        if (attributes.getType() != null) {
            Byte type = attributes.getType().getValue();
            LOGGER.debug("Type: {}", SftpFileType.getNameByType(type));
            appendByte(type);
        }
    }

    private void serializeSize() {
        if (attributes.getSize() != null) {
            Long size = attributes.getSize().getValue();
            LOGGER.debug("Size: {}", size);
            appendLong(size, DataFormatConstants.UINT64_SIZE);
        }
    }

    private void serializeUIdGId() {
        if (attributes.getUserId() != null) {
            Integer uId = attributes.getUserId().getValue();
            LOGGER.debug("UId: {}", uId);
            appendInt(uId, DataFormatConstants.UINT32_SIZE);
        }
        if (attributes.getGroupId() != null) {
            Integer gId = attributes.getGroupId().getValue();
            LOGGER.debug("GId: {}", gId);
            appendInt(gId, DataFormatConstants.UINT32_SIZE);
        }
    }

    private void serializeOwnerGroup() {
        if (attributes.getOwner() != null) {
            Integer ownerLength = attributes.getOwnerLength().getValue();
            LOGGER.debug("Owner length: {}", ownerLength);
            appendInt(ownerLength, DataFormatConstants.STRING_SIZE_LENGTH);
            String owner = attributes.getOwner().getValue();
            LOGGER.debug("Owner: {}", () -> backslashEscapeString(owner));
            appendString(owner, StandardCharsets.UTF_8);
        }
        if (attributes.getGroup() != null) {
            Integer groupLength = attributes.getGroupLength().getValue();
            LOGGER.debug("Group length: {}", groupLength);
            appendInt(groupLength, DataFormatConstants.STRING_SIZE_LENGTH);
            String group = attributes.getGroup().getValue();
            LOGGER.debug("Group: {}", () -> backslashEscapeString(group));
            appendString(group, StandardCharsets.UTF_8);
        }
    }

    private void serializePermissions() {
        if (attributes.getPermissions() != null) {
            Integer permissions = attributes.getPermissions().getValue();
            LOGGER.debug("Permissions: {}", permissions);
            appendInt(permissions, DataFormatConstants.UINT32_SIZE);
        }
    }

    private void serializeTimes() {
        if (attributes.getAccessTime() != null) {
            Integer aTime = attributes.getAccessTime().getValue();
            LOGGER.debug("ATime: {}", aTime);
            appendInt(aTime, DataFormatConstants.UINT32_SIZE);
        }
        if (attributes.getCreateTime() != null) {
            Integer cTime = attributes.getCreateTime().getValue();
            LOGGER.debug("CTime: {}", cTime);
            appendInt(cTime, DataFormatConstants.UINT32_SIZE);
        }
        if (attributes.getModifyTime() != null) {
            Integer mTime = attributes.getModifyTime().getValue();
            LOGGER.debug("MTime: {}", mTime);
            appendInt(mTime, DataFormatConstants.UINT32_SIZE);
        }
    }

    private void serializeAcl() {
        if (attributes.getAclEntriesCount() != null) {
            Integer aclLength = attributes.getAclLength().getValue();
            LOGGER.debug("AclLength: {}", aclLength);
            appendInt(aclLength, DataFormatConstants.UINT32_SIZE);

            Integer aclEntriesCount = attributes.getAclEntriesCount().getValue();
            LOGGER.debug("AclEntriesCount: {}", aclEntriesCount);
            appendInt(aclEntriesCount, DataFormatConstants.UINT32_SIZE);

            attributes
                    .getAclEntries()
                    .forEach(
                            aclEntry ->
                                    appendBytes(
                                            aclEntry.getHandler(null).getSerializer().serialize()));
        }
    }

    private void serializeExtendedAttributes() {
        if (attributes.getExtendedCount() != null) {
            Integer extendedCount = attributes.getExtendedCount().getValue();
            LOGGER.debug("ExtendedCount: {}", extendedCount);
            appendInt(extendedCount, DataFormatConstants.UINT32_SIZE);

            attributes
                    .getExtendedAttributes()
                    .forEach(
                            extendedAttribute ->
                                    appendBytes(
                                            extendedAttribute
                                                    .getHandler(null)
                                                    .getSerializer()
                                                    .serialize()));
        }
    }

    @Override
    protected final void serializeBytes() {
        serializeFlags();
        serializeType();
        serializeSize();
        serializeUIdGId();
        serializeOwnerGroup();
        serializePermissions();
        serializeTimes();
        serializeAcl();
        serializeExtendedAttributes();
    }
}
