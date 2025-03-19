/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.holder;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpFileExtendedAttribute;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpFileAttributesPreparator extends Preparator<SftpFileAttributes> {

    @Override
    public final void prepare(SftpFileAttributes object, Chooser chooser) {
        object.setFlags(
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME,
                SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED);

        Config config = chooser.getConfig();

        int flags = object.getFlags().getValue();
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE, config)) {
            object.setSize(0);
        } else {
            object.clearSize();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID, config)) {
            object.setUserId(0);
            object.setGroupId(0);
        } else {
            object.clearUserId();
            object.clearGroupId();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS, config)) {
            object.setPermissions(0);
        } else {
            object.clearPermissions();
        }

        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME, config)) {
            object.setAccessTime(0);
            object.setModifyTime(0);
        } else {
            object.clearAccessTime();
            object.clearModifyTime();
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
