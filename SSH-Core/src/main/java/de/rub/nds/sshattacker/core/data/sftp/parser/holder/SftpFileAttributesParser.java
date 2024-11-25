/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.constants.SftpFileType;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpFileAttributesParser extends Parser<SftpFileAttributes> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpFileAttributes attributes = new SftpFileAttributes();
    private final Chooser chooser;

    public SftpFileAttributesParser(byte[] array, Chooser chooser) {
        super(array);
        this.chooser = chooser;
    }

    public SftpFileAttributesParser(byte[] array, int startPosition, Chooser chooser) {
        super(array, startPosition);
        this.chooser = chooser;
    }

    private void parseFlags() {
        int flags = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setFlags(flags);
        LOGGER.debug("Flags: {}", flags);
    }

    private void parseType() {
        byte type = parseByteField(1);
        attributes.setType(type);
        LOGGER.debug("Type: {}", SftpFileType.getNameByType(type));
    }

    private void parseSize() {
        long size = parseLongField(DataFormatConstants.UINT64_SIZE);
        attributes.setSize(size);
        LOGGER.debug("Size: {}", size);
    }

    private void parseUIdGId() {
        int uId = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setUserId(uId);
        LOGGER.debug("UId: {}", uId);
        int gId = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setGroupId(gId);
        LOGGER.debug("GId: {}", gId);
    }

    private void parsePermissions() {
        int permissions = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setPermissions(permissions);
        LOGGER.debug("Permissions: {}", permissions);
    }

    private void parseAcModTime() {
        int aTime = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setAccessTime(aTime);
        LOGGER.debug("ATime: {}", aTime);
        int mTime = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setModifyTime(mTime);
        LOGGER.debug("MTime: {}", mTime);
    }

    private void parseAccessTime() {
        int accessTime = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setAccessTime(accessTime);
        LOGGER.debug("AccessTime: {}", accessTime);
    }

    private void parseCreateTime() {
        int createTime = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setCreateTime(createTime);
        LOGGER.debug("CreateTime: {}", createTime);
    }

    private void parseModifyTime() {
        int modifyTime = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setModifyTime(modifyTime);
        LOGGER.debug("ModifyTime: {}", modifyTime);
    }

    private void parseOwnerGroup() {
        int ownerLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        attributes.setOwnerLength(ownerLength);
        LOGGER.debug("Owner length: {}", ownerLength);
        String owner = parseByteString(ownerLength, StandardCharsets.UTF_8);
        attributes.setOwner(owner);
        LOGGER.debug("Owner: {}", () -> backslashEscapeString(owner));

        int groupLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        attributes.setGroupLength(groupLength);
        LOGGER.debug("Group length: {}", groupLength);
        String group = parseByteString(groupLength, StandardCharsets.UTF_8);
        attributes.setGroup(group);
        LOGGER.debug("Group: {}", () -> backslashEscapeString(group));
    }

    private void parseAcl() {
        int aclLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setAclLength(aclLength);
        LOGGER.debug("AclLength: {}", aclLength);

        int aclEntriesCount = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setAclEntriesCount(aclEntriesCount);
        LOGGER.debug("setAclEntriesCount: {}", aclEntriesCount);

        for (int aclEntryIdx = 0, aclEntryStartPointer = getPointer();
                aclEntryIdx < aclEntriesCount;
                aclEntryIdx++, aclEntryStartPointer = getPointer()) {

            SftpAclEntryParser aclEntryParser =
                    new SftpAclEntryParser(getArray(), aclEntryStartPointer);

            attributes.addAclEntry(aclEntryParser.parse(), true);
            setPointer(aclEntryParser.getPointer());
        }
    }

    private void parseExtendedAttributes() {
        int extendedCount = parseIntField(DataFormatConstants.UINT32_SIZE);
        attributes.setExtendedCount(extendedCount);
        LOGGER.debug("ExtendedCount: {}", extendedCount);

        for (int extendedAttrIndex = 0, extendedAttrStartPointer = getPointer();
                extendedAttrIndex < extendedCount;
                extendedAttrIndex++, extendedAttrStartPointer = getPointer()) {

            SftpFileExtendedAttributeParser extendedAttrParser =
                    new SftpFileExtendedAttributeParser(getArray(), extendedAttrStartPointer);

            attributes.addExtendedAttribute(extendedAttrParser.parse(), true);
            setPointer(extendedAttrParser.getPointer());
        }
    }

    @Override
    public final SftpFileAttributes parse() {
        parseFlags();

        if (chooser.getSftpNegotiatedVersion() > 3) {
            parseType();
        }

        int flags = attributes.getFlags().getValue();
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE)) {
            parseSize();
        }
        if (chooser.getSftpNegotiatedVersion() > 3) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_OWNERGROUP)) {
                parseOwnerGroup();
            }
        } else {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID)) {
                parseUIdGId();
            }
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS)) {
            parsePermissions();
        }
        if (chooser.getSftpNegotiatedVersion() > 3) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACCESSTIME)) {
                parseAccessTime();
            }
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_CREATETIME)) {
                parseCreateTime();
            }
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_MODIFYTIME)) {
                parseModifyTime();
            }
        } else {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME)) {
                parseAcModTime();
            }
        }

        if (chooser.getSftpNegotiatedVersion() > 3) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACL)) {
                parseAcl();
            }
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED)) {
            parseExtendedAttributes();
        }
        return attributes;
    }

    private static boolean isFlagSet(int attributes, SftpFileAttributeFlag attribute) {
        return (attributes & attribute.getValue()) != 0;
    }
}
