/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class SftpRequestMessagePreparator<T extends SftpRequestMessage<T>>
        extends SftpMessagePreparator<T> {

    protected SftpRequestMessagePreparator(
            Chooser chooser, T message, SftpPacketTypeConstant packetType) {
        super(chooser, message, packetType);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setRequestId(chooser.getContext().getSftpManager().getNextRequestId());
        prepareRequestSpecificContents();
    }

    protected abstract void prepareRequestSpecificContents();
}
