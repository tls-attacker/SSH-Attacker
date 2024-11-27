/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.response;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class SftpResponseMessagePreparator<T extends SftpResponseMessage<T>>
        extends SftpMessagePreparator<T> {

    protected SftpResponseMessagePreparator(
            Chooser chooser, T message, SftpPacketTypeConstant packetType) {
        super(chooser, message, packetType);
    }

    public void prepareMessageSpecificContents() {
        // Request identifier should be set by SftpManager in handleRequestMessage()
        if (getObject().getRequestId() == null
                || getObject().getRequestId().getOriginalValue() == null) {
            getObject().setRequestId(chooser.getContext().getSftpManager().getNextRequestId());
        }
        prepareResponseSpecificContents();
    }

    protected abstract void prepareResponseSpecificContents();
}
