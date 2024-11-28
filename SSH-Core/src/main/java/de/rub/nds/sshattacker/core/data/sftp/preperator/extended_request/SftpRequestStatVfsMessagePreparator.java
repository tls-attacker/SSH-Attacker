/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestStatVfsMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestStatVfsMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestStatVfsMessage> {

    public SftpRequestStatVfsMessagePreparator(Chooser chooser, SftpRequestStatVfsMessage message) {
        super(chooser, message, SftpExtension.STAT_VFS_OPENSSH_COM);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        getObject().setSoftlyPath("/etc/", true, chooser.getConfig());
    }
}
