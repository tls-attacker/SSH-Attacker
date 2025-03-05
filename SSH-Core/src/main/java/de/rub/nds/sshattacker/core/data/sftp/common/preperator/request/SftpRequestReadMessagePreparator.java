/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestReadMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestReadMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestReadMessage> {

    public SftpRequestReadMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_READ);
    }

    @Override
    public void prepareRequestSpecificContents(SftpRequestReadMessage object, Chooser chooser) {
        object.setHandle(
                chooser.getContext().getSftpManager().getFileHandle(object.getConfigHandleIndex()),
                true);

        object.setOffset(0);

        object.setLength(100000000);
    }
}
