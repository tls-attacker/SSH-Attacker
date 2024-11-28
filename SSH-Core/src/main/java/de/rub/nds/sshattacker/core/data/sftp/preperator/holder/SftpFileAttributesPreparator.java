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
        getObject()
                .setSoftlyFlags(
                        SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE,
                        SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID,
                        SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS,
                        SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME,
                        SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED);

        if (chooser.getSftpNegotiatedVersion() > 3
                || !chooser.getConfig().getRespectSftpNegotiatedVersion()) {
            getObject().setSoftlyType(SftpFileType.SSH_FILEXFER_TYPE_REGULAR);
        } else {
            getObject().clearType();
        }

        int flags = getObject().getFlags().getValue();
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE)) {
            getObject().setSoftlySize(0);
        } else {
            getObject().clearSize();
        }

        if (chooser.getSftpNegotiatedVersion() > 3
                || !chooser.getConfig().getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_OWNERGROUP)) {
                getObject().setSoftlyOwner("ssh-attacker", true, chooser.getConfig());

                getObject().setSoftlyGroup("nds", true, chooser.getConfig());
            } else {
                getObject().clearOwner();
                getObject().clearGroup();
            }
            getObject().clearUserId();
            getObject().clearGroupId();
        } else {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID)) {
                getObject().setSoftlyUserId(0);
                getObject().setSoftlyGroupId(0);
            } else {
                getObject().clearUserId();
                getObject().clearGroupId();
            }
            getObject().clearOwner();
            getObject().clearGroup();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS)) {
            getObject().setSoftlyPermissions(0);
        } else {
            getObject().clearPermissions();
        }

        if (chooser.getSftpNegotiatedVersion() > 3
                || !chooser.getConfig().getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACCESSTIME)) {
                getObject().setSoftlyAccessTime(0);
            } else {
                getObject().clearAccessTime();
            }
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_CREATETIME)) {
                getObject().setSoftlyCreateTime(0);
            } else {
                getObject().clearCreateTime();
            }

            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_MODIFYTIME)) {
                getObject().setSoftlyModifyTime(0);
            } else {
                getObject().clearModifyTime();
            }
        } else {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME)) {
                getObject().setSoftlyAccessTime(0);
                getObject().setSoftlyModifyTime(0);
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
                getObject()
                        .setSoftlyAclEntriesCount(
                                getObject().getAclEntries().size(), chooser.getConfig());
                getObject()
                        .getAclEntries()
                        .forEach(
                                aclEntry ->
                                        aclEntry.getHandler(chooser.getContext())
                                                .getPreparator()
                                                .prepare());
                getObject()
                        .setSoftlyAclLength(
                                DataFormatConstants.UINT32_SIZE
                                        + getObject().getAclEntries().size()
                                                * (DataFormatConstants.UINT32_SIZE * 3
                                                        + DataFormatConstants.STRING_SIZE_LENGTH)
                                        + getObject().getAclEntries().stream()
                                                .map(SftpAclEntry::getWhoLength)
                                                .mapToInt(ModifiableVariable::getValue)
                                                .sum(),
                                chooser.getConfig());

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
            getObject()
                    .setSoftlyExtendedCount(
                            getObject().getExtendedAttributes().size(), chooser.getConfig());

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
        return (attributes & attribute.getValue()) != 0
                || !chooser.getConfig().getRespectSftpAttributesFlags();
    }
}
