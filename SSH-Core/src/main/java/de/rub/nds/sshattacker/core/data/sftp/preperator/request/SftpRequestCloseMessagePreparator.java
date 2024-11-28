/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestCloseMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestCloseMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestCloseMessage> {

    public SftpRequestCloseMessagePreparator(Chooser chooser, SftpRequestCloseMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_CLOSE);
    }

    @Override
    public void prepareRequestSpecificContents() {
        getObject()
                .setSoftlyHandle(
                        chooser.getContext().getSftpManager().getFileOrDirectoryHandle(),
                        true,
                        chooser.getConfig());
    }
}
