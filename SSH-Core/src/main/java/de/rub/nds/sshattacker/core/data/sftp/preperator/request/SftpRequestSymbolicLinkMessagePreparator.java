/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestSymbolicLinkMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestSymbolicLinkMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestSymbolicLinkMessage> {

    public SftpRequestSymbolicLinkMessagePreparator(
            Chooser chooser, SftpRequestSymbolicLinkMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_SYMLINK);
    }

    @Override
    public void prepareRequestSpecificContents() {
        getObject().setSoftlyPath("/bin/sh", true, chooser.getConfig());

        getObject().setSoftlyTargetPath("/tmp/ssh-attacker-sh", true, chooser.getConfig());
    }
}
