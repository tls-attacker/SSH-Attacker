/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.attribute;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
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

    private void serializeSize() {
        Long size = attributes.getSize().getValue();
        LOGGER.debug("Size: {}", size);
        appendLong(size, DataFormatConstants.UINT64_SIZE);
    }

    private void serializeUIdGId() {
        Integer uId = attributes.getUId().getValue();
        LOGGER.debug("UId: {}", uId);
        appendInt(uId, DataFormatConstants.UINT32_SIZE);
        Integer gId = attributes.getGId().getValue();
        LOGGER.debug("GId: {}", gId);
        appendInt(gId, DataFormatConstants.UINT32_SIZE);
    }

    private void serializePermissions() {
        Integer permissions = attributes.getPermissions().getValue();
        LOGGER.debug("Permissions: {}", permissions);
        appendInt(permissions, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeAcModTime() {
        Integer aTime = attributes.getATime().getValue();
        LOGGER.debug("ATime: {}", aTime);
        appendInt(aTime, DataFormatConstants.UINT32_SIZE);
        Integer mTime = attributes.getMTime().getValue();
        LOGGER.debug("MTime: {}", mTime);
        appendInt(mTime, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeExtendedAttributes() {
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

    @Override
    protected final void serializeBytes() {
        serializeFlags();
        int flags = attributes.getFlags().getValue();
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE)) {
            serializeSize();
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID)) {
            serializeUIdGId();
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS)) {
            serializePermissions();
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME)) {
            serializeAcModTime();
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED)) {
            serializeExtendedAttributes();
        }
    }

    private static boolean isFlagSet(int attributes, SftpFileAttributeFlag attribute) {
        return (attributes & attribute.getValue()) != 0;
    }
}
