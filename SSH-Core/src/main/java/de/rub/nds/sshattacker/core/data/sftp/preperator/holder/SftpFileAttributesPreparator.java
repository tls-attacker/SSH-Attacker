/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.holder;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.constants.SftpFileType;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpAclEntry;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileExtendedAttribute;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpFileAttributesPreparator extends Preparator<SftpFileAttributes> {

    public SftpFileAttributesPreparator(Chooser chooser, SftpFileAttributes attribute) {
        super(chooser, attribute);
    }

    @Override
    public final void prepare() {
        if (getObject().getFlags() == null || getObject().getFlags().getOriginalValue() == null) {
            getObject()
                    .setFlags(
                            SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE,
                            SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID,
                            SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS,
                            SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME,
                            SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED);
        }

        if (chooser.getSftpNegotiatedVersion() > 3
                || !chooser.getConfig().getRespectSftpNegotiatedVersion()) {
            if (getObject().getType() == null || getObject().getType().getOriginalValue() == null) {
                getObject().setType(SftpFileType.SSH_FILEXFER_TYPE_REGULAR);
            }
        } else {
            getObject().clearType();
        }

        int flags = getObject().getFlags().getValue();
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE)) {
            if (getObject().getSize() == null || getObject().getSize().getOriginalValue() == null) {
                getObject().setSize(0);
            }
        } else {
            getObject().clearSize();
        }

        if (chooser.getSftpNegotiatedVersion() > 3
                || !chooser.getConfig().getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_OWNERGROUP)) {
                if (getObject().getOwner() == null || getObject().getOwner().getOriginalValue() == null) {
                    getObject().setOwner("ssh-attacker", true);
                }
                if (getObject().getOwnerLength() == null || getObject().getOwnerLength().getOriginalValue() == null) {
                    getObject().setOwnerLength(getObject().getOwner().getValue().length());
                }

                if (getObject().getGroup() == null || getObject().getGroup().getOriginalValue() == null) {
                    getObject().setGroup("nds", true);
                }
                if (getObject().getGroupLength() == null || getObject().getGroupLength().getOriginalValue() == null) {
                    getObject().setGroupLength(getObject().getGroup().getValue().length());
                }
            } else {
                getObject().clearOwner();
                getObject().clearGroup();
            }
            getObject().clearUserId();
            getObject().clearGroupId();
        } else {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID)) {
                if (getObject().getUserId() == null || getObject().getUserId().getOriginalValue() == null) {
                    getObject().setUserId(0);
                }
                if (getObject().getGroupId() == null || getObject().getGroupId().getOriginalValue() == null) {
                    getObject().setGroupId(0);
                }
            } else {
                getObject().clearUserId();
                getObject().clearGroupId();
            }
            getObject().clearOwner();
            getObject().clearGroup();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS)) {
            if (getObject().getPermissions() == null || getObject().getPermissions().getOriginalValue() == null) {
                getObject().setPermissions(0);
            }
        } else {
            getObject().clearPermissions();
        }

        if (chooser.getSftpNegotiatedVersion() > 3
                || !chooser.getConfig().getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACCESSTIME)) {
                if (getObject().getAccessTime() == null || getObject().getAccessTime().getOriginalValue() == null) {
                    getObject().setAccessTime(0);
                }
            } else {
                getObject().clearAccessTime();
            }
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_CREATETIME)) {
                if (getObject().getCreateTime() == null || getObject().getCreateTime().getOriginalValue() == null) {
                    getObject().setCreateTime(0);
                }
            } else {
                getObject().clearCreateTime();
            }

            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_MODIFYTIME)) {
                if (getObject().getModifyTime() == null || getObject().getModifyTime().getOriginalValue() == null) {
                    getObject().setModifyTime(0);
                }
            } else {
                getObject().clearModifyTime();
            }
        } else {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME)) {
                if (getObject().getAccessTime() == null || getObject().getAccessTime().getOriginalValue() == null) {
                    getObject().setAccessTime(0);
                }
                if (getObject().getModifyTime() == null || getObject().getModifyTime().getOriginalValue() == null) {
                    getObject().setModifyTime(0);
                }
            } else {
                getObject().clearAccessTime();
                getObject().clearModifyTime();
            }
            getObject().clearCreateTime();
        }

        if (chooser.getSftpNegotiatedVersion() > 3
                || !chooser.getConfig().getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACL)) {
                if (getObject().getAclEntries().isEmpty()) {
                    getObject().addAclEntry(new SftpAclEntry());
                }
                if (getObject().getAclEntriesCount() == null || getObject().getAclEntriesCount().getOriginalValue() == null) {
                    getObject().setAclEntriesCount(getObject().getAclEntries().size());
                }
                getObject()
                        .getAclEntries()
                        .forEach(
                                aclEntry ->
                                        aclEntry.getHandler(chooser.getContext())
                                                .getPreparator()
                                                .prepare());
                getObject()
                        .setAclLength(
                                DataFormatConstants.UINT32_SIZE
                                        + getObject().getAclEntries().size()
                                                * (DataFormatConstants.UINT32_SIZE * 3
                                                        + DataFormatConstants.STRING_SIZE_LENGTH)
                                        + getObject().getAclEntries().stream()
                                                .map(SftpAclEntry::getWhoLength)
                                                .mapToInt(ModifiableVariable::getValue)
                                                .sum());
            } else {
                getObject().clearAcl();
            }
        } else {
            getObject().clearAcl();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED)) {
            if (getObject().getExtendedAttributes().isEmpty()) {
                getObject().addExtendedAttribute(new SftpFileExtendedAttribute());
            }
            if (getObject().getExtendedCount() == null || getObject().getExtendedCount().getOriginalValue() == null) {
                getObject().setExtendedCount(getObject().getExtendedAttributes().size());
            }
            getObject()
                    .getExtendedAttributes()
                    .forEach(
                            extendedAttribute ->
                                    extendedAttribute
                                            .getHandler(chooser.getContext())
                                            .getPreparator()
                                            .prepare());
        } else {
            getObject().clearExtendedAttributes();
        }
    }

    private boolean isFlagSet(int attributes, SftpFileAttributeFlag attribute) {
        return chooser.getConfig().getRespectSftpAttributesFlags()
                || (attributes & attribute.getValue()) != 0;
    }
}
