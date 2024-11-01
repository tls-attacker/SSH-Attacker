/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestPosixRenameMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestPosixRenameMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestPosixRenameMessage> {

    public SftpRequestPosixRenameMessagePreparator(
            Chooser chooser, SftpRequestPosixRenameMessage message) {
        super(chooser, message, SftpExtension.POSIX_RENAME_OPENSSH_COM);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        if (getObject().getPath() == null) {
            getObject().setPath("/etc/passwd", true);
        }
        if (getObject().getPathLength() == null) {
            getObject().setPathLength(getObject().getPath().getValue().length());
        }

        if (getObject().getNewPath() == null) {
            getObject().setNewPath("/etc/passwd-new", true);
        }
        if (getObject().getNewPathLength() == null) {
            getObject().setNewPathLength(getObject().getNewPath().getValue().length());
        }
    }
}
