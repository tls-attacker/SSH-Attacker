/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

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
        int flags = parseIntField();
        attributes.setFlags(flags);
        LOGGER.debug("Flags: {}", flags);
    }

    private void parseType() {
        byte type = parseByteField();
        attributes.setType(type);
        LOGGER.debug("Type: {}", SftpFileType.getNameByType(type));
    }

    private void parseSize() {
        long size = parseLongField();
        attributes.setSize(size);
        LOGGER.debug("Size: {}", size);
    }

    private void parseUIdGId() {
        int uId = parseIntField();
        attributes.setUserId(uId);
        LOGGER.debug("UId: {}", uId);
        int gId = parseIntField();
        attributes.setGroupId(gId);
        LOGGER.debug("GId: {}", gId);
    }

    private void parsePermissions() {
        int permissions = parseIntField();
        attributes.setPermissions(permissions);
        LOGGER.debug("Permissions: {}", permissions);
    }

    private void parseAcModTime() {
        int aTime = parseIntField();
        attributes.setAccessTime(aTime);
        LOGGER.debug("ATime: {}", aTime);
        int mTime = parseIntField();
        attributes.setModifyTime(mTime);
        LOGGER.debug("MTime: {}", mTime);
    }

    private void parseAccessTime() {
        long accessTimeLong = parseLongField();
        attributes.setAccessTimeLong(accessTimeLong);
        LOGGER.debug("AccessTime: {}", accessTimeLong);
    }

    private void parseAccessTimeNanoseconds() {
        int accessTimeNanoseconds = parseIntField();
        attributes.setAccessTimeNanoseconds(accessTimeNanoseconds);
        LOGGER.debug("AccessTimeNanoseconds: {}", accessTimeNanoseconds);
    }

    private void parseCreateTime() {
        long createTimeLong = parseLongField();
        attributes.setCreateTimeLong(createTimeLong);
        LOGGER.debug("CreateTime: {}", createTimeLong);
    }

    private void parseCreateTimeNanoseconds() {
        int createTimeNanoseconds = parseIntField();
        attributes.setCreateTimeNanoseconds(createTimeNanoseconds);
        LOGGER.debug("CreateTimeNanoseconds: {}", createTimeNanoseconds);
    }

    private void parseModifyTime() {
        long modifyTimeLong = parseLongField();
        attributes.setModifyTimeLong(modifyTimeLong);
        LOGGER.debug("ModifyTime: {}", modifyTimeLong);
    }

    private void parseModifyTimeNanoseconds() {
        int modifyTimeNanoseconds = parseIntField();
        attributes.setModifyTimeNanoseconds(modifyTimeNanoseconds);
        LOGGER.debug("ModifyTimeNanoseconds: {}", modifyTimeNanoseconds);
    }

    private void parseOwnerGroup() {
        int ownerLength = parseIntField();
        attributes.setOwnerLength(ownerLength);
        LOGGER.debug("Owner length: {}", ownerLength);
        String owner = parseByteString(ownerLength, StandardCharsets.UTF_8);
        attributes.setOwner(owner);
        LOGGER.debug("Owner: {}", () -> backslashEscapeString(owner));

        int groupLength = parseIntField();
        attributes.setGroupLength(groupLength);
        LOGGER.debug("Group length: {}", groupLength);
        String group = parseByteString(groupLength, StandardCharsets.UTF_8);
        attributes.setGroup(group);
        LOGGER.debug("Group: {}", () -> backslashEscapeString(group));
    }

    private void parseAcl() {
        int aclLength = parseIntField();
        attributes.setAclLength(aclLength);
        LOGGER.debug("AclLength: {}", aclLength);

        int aclEntriesCount = parseIntField();
        attributes.setAclEntriesCount(aclEntriesCount);
        LOGGER.debug("setAclEntriesCount: {}", aclEntriesCount);

        for (int aclEntryIdx = 0, aclEntryStartPointer = getPointer();
                aclEntryIdx < aclEntriesCount;
                aclEntryIdx++, aclEntryStartPointer = getPointer()) {

            SftpAclEntryParser aclEntryParser =
                    new SftpAclEntryParser(getArray(), aclEntryStartPointer);

            attributes.addAclEntry(aclEntryParser.parse());
            setPointer(aclEntryParser.getPointer());
        }
    }

    private void parseExtendedAttributes() {
        int extendedCount = parseIntField();
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
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SUBSECOND_TIMES)) {
                parseAccessTimeNanoseconds();
            }
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_CREATETIME)) {
                parseCreateTime();
            }
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SUBSECOND_TIMES)) {
                parseCreateTimeNanoseconds();
            }
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_MODIFYTIME)) {
                parseModifyTime();
            }
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SUBSECOND_TIMES)) {
                parseModifyTimeNanoseconds();
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
