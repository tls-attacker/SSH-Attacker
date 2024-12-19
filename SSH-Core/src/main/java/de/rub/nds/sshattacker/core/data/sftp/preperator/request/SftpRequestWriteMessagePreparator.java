/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestWriteMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestWriteMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestWriteMessage> {

    public SftpRequestWriteMessagePreparator(Chooser chooser, SftpRequestWriteMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_WRITE);
    }

    @Override
    public void prepareRequestSpecificContents() {

        object.setSoftlyHandle(chooser.getContext().getSftpManager().getFileHandle(), true, config);

        object.setSoftlyOffset(0);

        object.setSoftlyData(new byte[100], true, config);
    }
}
