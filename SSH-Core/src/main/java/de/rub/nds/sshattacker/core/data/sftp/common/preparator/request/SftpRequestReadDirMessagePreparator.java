/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestReadDirMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestReadDirMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestReadDirMessage> {

    public SftpRequestReadDirMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_READDIR);
    }

    @Override
    protected void prepareRequestSpecificContents(
            SftpRequestReadDirMessage object, Chooser chooser) {
        object.setHandle(
                chooser.getContext()
                        .getSftpManager()
                        .getDirectoryHandle(object.getConfigHandleIndex()),
                true);
    }
}
