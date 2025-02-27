/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.preperator.holder;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.constants.SftpFileType;
import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpAclEntry;
import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpFileExtendedAttribute;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.holder.SftpV4FileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpV4FileAttributesPreparator extends Preparator<SftpV4FileAttributes> {

    @Override
    public final void prepare(SftpV4FileAttributes object, Chooser chooser) {
        object.setFlags(
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_OWNERGROUP,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACCESSTIME,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_CREATETIME,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_MODIFYTIME,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SUBSECOND_TIMES,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACL,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED);

        Config config = chooser.getConfig();
        object.setType(SftpFileType.SSH_FILEXFER_TYPE_REGULAR);

        int flags = object.getFlags().getValue();
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE, config)) {
            object.setSize(0);
        } else {
            object.clearSize();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_OWNERGROUP, config)) {
            object.setOwner("ssh-attacker", true);

            object.setGroup("nds", true);
        } else {
            object.clearOwner();
            object.clearGroup();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS, config)) {
            object.setPermissions(0);
        } else {
            object.clearPermissions();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACCESSTIME, config)) {
            object.setAccessTimeLong(0);
        } else {
            object.clearAccessTimeLong();
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_CREATETIME, config)) {
            object.setCreateTimeLong(0);
        } else {
            object.clearCreateTimeLong();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_MODIFYTIME, config)) {
            object.setModifyTimeLong(0);
        } else {
            object.clearModifyTimeLong();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SUBSECOND_TIMES, config)) {
            object.setAccessTimeNanoseconds(0);
            object.setCreateTimeNanoseconds(0);
            object.setModifyTimeNanoseconds(0);
        } else {
            object.clearAllNanoseconds();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACL, config)) {
            if (object.getAclEntries().isEmpty()) {
                object.addAclEntry(new SftpAclEntry());
            }
            object.setAclEntriesCount(object.getAclEntries().size());
            object.getAclEntries().forEach(aclEntry -> aclEntry.prepare(chooser));
            object.setAclLength(
                    DataFormatConstants.UINT32_SIZE
                            + object.getAclEntries().size()
                                    * (DataFormatConstants.UINT32_SIZE * 3
                                            + DataFormatConstants.STRING_SIZE_LENGTH)
                            + object.getAclEntries().stream()
                                    .map(SftpAclEntry::getWhoLength)
                                    .mapToInt(ModifiableVariable::getValue)
                                    .sum());

        } else {
            object.clearAcl();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED, config)) {
            if (object.getExtendedAttributes().isEmpty()) {
                object.addExtendedAttribute(new SftpFileExtendedAttribute());
            }
            object.setExtendedCount(object.getExtendedAttributes().size());

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
