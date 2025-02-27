/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.parser.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.constants.SftpFileType;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.holder.SftpAclEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.holder.SftpFileExtendedAttributeParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.holder.SftpV4FileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpV4FileAttributesParser extends Parser<SftpV4FileAttributes> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpV4FileAttributes attributes = new SftpV4FileAttributes();

    public SftpV4FileAttributesParser(byte[] array) {
        super(array);
    }

    public SftpV4FileAttributesParser(byte[] array, int startPosition) {
        super(array, startPosition);
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

    private void parsePermissions() {
        int permissions = parseIntField();
        attributes.setPermissions(permissions);
        LOGGER.debug("Permissions: {}", permissions);
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
    public final SftpV4FileAttributes parse() {
        parseFlags();

        parseType();

        int flags = attributes.getFlags().getValue();
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE)) {
            parseSize();
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_OWNERGROUP)) {
            parseOwnerGroup();
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS)) {
            parsePermissions();
        }
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

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACL)) {
            parseAcl();
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
