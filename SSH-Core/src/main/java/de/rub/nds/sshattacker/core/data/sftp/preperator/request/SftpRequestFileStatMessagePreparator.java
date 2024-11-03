/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestFileStatMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestFileStatMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestFileStatMessage> {

    public SftpRequestFileStatMessagePreparator(
            Chooser chooser, SftpRequestFileStatMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_FSTAT);
    }

    @Override
    public void prepareRequestSpecificContents() {
        getObject()
                .setHandle(chooser.getContext().getSftpManager().getFileOrDirectoryHandle(), true);
    }
}
