/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.attribute;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
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
        ArrayConverter.intToBytes(
                attributes.getFlags().getValue(), DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("Flags: {}", attributes.getFlags().getValue());
        appendInt(attributes.getFlags().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeSize() {
        LOGGER.debug("Size: {}", attributes.getSize().getValue());
        appendLong(attributes.getSize().getValue(), DataFormatConstants.UINT64_SIZE);
    }

    private void serializeUIdGId() {
        LOGGER.debug("UId: {}", attributes.getUId().getValue());
        appendInt(attributes.getUId().getValue(), DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("GId: {}", attributes.getGId().getValue());
        appendInt(attributes.getGId().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializePermissions() {
        LOGGER.debug("Permissions: {}", attributes.getPermissions().getValue());
        appendInt(attributes.getPermissions().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeAcModTime() {
        LOGGER.debug("ATime: {}", attributes.getATime().getValue());
        appendInt(attributes.getATime().getValue(), DataFormatConstants.UINT32_SIZE);
        LOGGER.debug("MTime: {}", attributes.getMTime().getValue());
        appendInt(attributes.getMTime().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeExtendedAttributes() {
        LOGGER.debug("ExtendedCount: {}", attributes.getExtendedCount().getValue());
        appendInt(attributes.getExtendedCount().getValue(), DataFormatConstants.UINT32_SIZE);

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
