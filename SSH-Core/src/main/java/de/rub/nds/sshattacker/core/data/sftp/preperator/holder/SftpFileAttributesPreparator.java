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
        object.setSoftlyFlags(
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED);

        if (chooser.getSftpNegotiatedVersion() > 3 || !config.getRespectSftpNegotiatedVersion()) {
            object.setSoftlyType(SftpFileType.SSH_FILEXFER_TYPE_REGULAR);
        } else {
            object.clearType();
        }

        int flags = object.getFlags().getValue();
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE)) {
            object.setSoftlySize(0);
        } else {
            object.clearSize();
        }

        if (chooser.getSftpNegotiatedVersion() > 3 || !config.getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_OWNERGROUP)) {
                object.setSoftlyOwner("ssh-attacker", true, config);

                object.setSoftlyGroup("nds", true, config);
            } else {
                object.clearOwner();
                object.clearGroup();
            }
            object.clearUserId();
            object.clearGroupId();
        } else {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID)) {
                object.setSoftlyUserId(0);
                object.setSoftlyGroupId(0);
            } else {
                object.clearUserId();
                object.clearGroupId();
            }
            object.clearOwner();
            object.clearGroup();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS)) {
            object.setSoftlyPermissions(0);
        } else {
            object.clearPermissions();
        }

        if (chooser.getSftpNegotiatedVersion() > 3 || !config.getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACCESSTIME)) {
                object.setSoftlyAccessTime(0);
            } else {
                object.clearAccessTime();
            }
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_CREATETIME)) {
                object.setSoftlyCreateTime(0);
            } else {
                object.clearCreateTime();
            }

            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_MODIFYTIME)) {
                object.setSoftlyModifyTime(0);
            } else {
                object.clearModifyTime();
            }
        } else {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME)) {
                object.setSoftlyAccessTime(0);
                object.setSoftlyModifyTime(0);
            } else {
                object.clearAccessTime();
                object.clearModifyTime();
            }
            object.clearCreateTime();
        }

        if (chooser.getSftpNegotiatedVersion() > 3 || !config.getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACL)) {
                if (object.getAclEntries().isEmpty()) {
                    object.addAclEntry(new SftpAclEntry());
                }
                object.setSoftlyAclEntriesCount(object.getAclEntries().size(), config);
                object.getAclEntries()
                        .forEach(
                                aclEntry ->
                                        aclEntry.getHandler(chooser.getContext())
                                                .getPreparator()
                                                .prepare());
                object.setSoftlyAclLength(
                        DataFormatConstants.UINT32_SIZE
                                + object.getAclEntries().size()
                                        * (DataFormatConstants.UINT32_SIZE * 3
                                                + DataFormatConstants.STRING_SIZE_LENGTH)
                                + object.getAclEntries().stream()
                                        .map(SftpAclEntry::getWhoLength)
                                        .mapToInt(ModifiableVariable::getValue)
                                        .sum(),
                        config);

            } else {
                object.clearAcl();
            }
        } else {
            object.clearAcl();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED)) {
            if (object.getExtendedAttributes().isEmpty()) {
                object.addExtendedAttribute(new SftpFileExtendedAttribute());
            }
            object.setSoftlyExtendedCount(object.getExtendedAttributes().size(), config);

            object.getExtendedAttributes()
                    .forEach(
                            extendedAttribute ->
                                    extendedAttribute
                                            .getHandler(chooser.getContext())
                                            .getPreparator()
                                            .prepare());
        } else {
            object.clearExtendedAttributes();
        }
    }

    private boolean isFlagSet(int attributes, SftpFileAttributeFlag attribute) {
        return (attributes & attribute.getValue()) != 0 || !config.getRespectSftpAttributesFlags();
    }
}
