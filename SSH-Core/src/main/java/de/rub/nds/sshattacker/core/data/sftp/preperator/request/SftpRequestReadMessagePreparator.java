/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestReadMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestReadMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestReadMessage> {

    public SftpRequestReadMessagePreparator(Chooser chooser, SftpRequestReadMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_READ);
    }

    @Override
    public void prepareRequestSpecificContents() {
        getObject().setHandle(chooser.getContext().getSftpManager().getFileHandle(), true);

        if (getObject().getOffset() == null || getObject().getOffset().getOriginalValue() == null) {
            getObject().setOffset(0);
        }

        if (getObject().getLength() == null || getObject().getLength().getOriginalValue() == null) {
            getObject().setLength(100000000);
        }
    }
}
