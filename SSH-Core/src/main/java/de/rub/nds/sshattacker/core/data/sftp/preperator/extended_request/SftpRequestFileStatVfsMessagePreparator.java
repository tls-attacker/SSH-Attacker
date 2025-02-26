/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestFileStatVfsMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestFileStatVfsMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestFileStatVfsMessage> {

    public SftpRequestFileStatVfsMessagePreparator() {
        super(SftpExtension.F_STAT_VFS_OPENSSH_COM);
    }

    @Override
    public void prepareRequestExtendedSpecificContents(
            SftpRequestFileStatVfsMessage object, Chooser chooser) {
        object.setHandle(chooser.getContext().getSftpManager().getFileOrDirectoryHandle(), true);
    }
}
