/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.holder;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.constants.SftpFileType;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpAclEntry;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileExtendedAttribute;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpFileAttributesPreparator extends Preparator<SftpFileAttributes> {

    @Override
    public final void prepare(SftpFileAttributes object, Chooser chooser) {
        object.setSoftlyFlags(
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED);

        Config config = chooser.getConfig();
        if (chooser.getSftpNegotiatedVersion() > 3 || !config.getRespectSftpNegotiatedVersion()) {
            object.setSoftlyType(SftpFileType.SSH_FILEXFER_TYPE_REGULAR);
        } else {
            object.clearType();
        }

        int flags = object.getFlags().getValue();
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE, config)) {
            object.setSoftlySize(0);
        } else {
            object.clearSize();
        }

        if (chooser.getSftpNegotiatedVersion() > 3 || !config.getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_OWNERGROUP, config)) {
                object.setSoftlyOwner("ssh-attacker", true, config);

                object.setSoftlyGroup("nds", true, config);
            } else {
                object.clearOwner();
                object.clearGroup();
            }
            object.clearUserId();
            object.clearGroupId();
        } else {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID, config)) {
                object.setSoftlyUserId(0);
                object.setSoftlyGroupId(0);
            } else {
                object.clearUserId();
                object.clearGroupId();
            }
            object.clearOwner();
            object.clearGroup();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS, config)) {
            object.setSoftlyPermissions(0);
        } else {
            object.clearPermissions();
        }

        if (chooser.getSftpNegotiatedVersion() > 3 || !config.getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACCESSTIME, config)) {
                object.setSoftlyAccessTimeLong(0);
            } else {
                object.clearAccessTimeLong();
            }
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_CREATETIME, config)) {
                object.setSoftlyCreateTimeLong(0);
            } else {
                object.clearCreateTimeLong();
            }

            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_MODIFYTIME, config)) {
                object.setSoftlyModifyTimeLong(0);
            } else {
                object.clearModifyTimeLong();
            }
        } else {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME, config)) {
                object.setSoftlyAccessTime(0);
                object.setSoftlyModifyTime(0);
            } else {
                object.clearAccessTime();
                object.clearModifyTime();
            }
            object.clearAllLongTimes();
        }
        if (chooser.getSftpNegotiatedVersion() > 3 || !config.getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SUBSECOND_TIMES, config)) {
                object.setSoftlyAccessTimeNanoseconds(0);
                object.setSoftlyCreateTimeNanoseconds(0);
                object.setSoftlyModifyTimeNanoseconds(0);
            } else {
                object.clearAllNanoseconds();
            }
        } else {
            object.clearAllNanoseconds();
        }

        if (chooser.getSftpNegotiatedVersion() > 3 || !config.getRespectSftpNegotiatedVersion()) {
            if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACL, config)) {
                if (object.getAclEntries().isEmpty()) {
                    object.addAclEntry(new SftpAclEntry());
                }
                object.setSoftlyAclEntriesCount(object.getAclEntries().size(), config);
                object.getAclEntries().forEach(aclEntry -> aclEntry.prepare(chooser));
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

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED, config)) {
            if (object.getExtendedAttributes().isEmpty()) {
                object.addExtendedAttribute(new SftpFileExtendedAttribute());
            }
            object.setSoftlyExtendedCount(object.getExtendedAttributes().size(), config);

            object.getExtendedAttributes()
                    .forEach(extendedAttribute -> extendedAttribute.prepare(chooser));
        } else {
            object.clearExtendedAttributes();
        }
    }

    private static boolean isFlagSet(
            int attributes, SftpFileAttributeFlag attribute, Config config) {
        return (attributes & attribute.getValue()) != 0 || !config.getRespectSftpAttributesFlags();
    }
}
