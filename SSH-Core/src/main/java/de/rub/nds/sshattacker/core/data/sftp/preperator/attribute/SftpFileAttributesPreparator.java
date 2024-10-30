/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.attribute;

import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpFileAttributesPreparator extends Preparator<SftpFileAttributes> {

    public SftpFileAttributesPreparator(Chooser chooser, SftpFileAttributes attribute) {
        super(chooser, attribute);
    }

    @Override
    public final void prepare() {
        if (getObject().getFlags() == null) {
            getObject()
                    .setFlags(
                            getFlags(
                                    SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE,
                                    SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID,
                                    SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS,
                                    SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME,
                                    SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED));
        }
        if (getObject().getSize() == null) {
            getObject().setSize(0);
        }
        if (getObject().getUId() == null) {
            getObject().setUId(0);
        }
        if (getObject().getGId() == null) {
            getObject().setGId(0);
        }
        if (getObject().getPermissions() == null) {
            getObject().setPermissions(0);
        }
        if (getObject().getATime() == null) {
            getObject().setATime(0);
        }
        if (getObject().getMTime() == null) {
            getObject().setMTime(0);
        }
        if (getObject().getExtendedCount() == null) {
            getObject().setExtendedCount(0);
        }

        getObject()
            .getExtendedAttributes()
            .forEach(
                extendedAttribute ->
                    extendedAttribute
                        .getHandler(chooser.getContext())
                        .getPreparator()
                        .prepare());
    }

    public static int getFlags(SftpFileAttributeFlag... attributes) {
        int result = 0;
        for (SftpFileAttributeFlag attribute : attributes) {
            result |= attribute.getValue(); // Use bitwise OR to set each flag
        }
        return result;
    }
}
