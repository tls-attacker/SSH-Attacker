/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestCloseMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestCloseMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestCloseMessage> {

    public SftpRequestCloseMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_CLOSE);
    }

    @Override
    protected void prepareRequestSpecificContents(SftpRequestCloseMessage object, Chooser chooser) {
        object.setHandle(
                chooser.getContext()
                        .getSftpManager()
                        .getFileOrDirectoryHandle(object.getConfigHandleIndex()),
                true);
    }
}
