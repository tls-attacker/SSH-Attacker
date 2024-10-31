/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class SftpRequestMessagePreparator<T extends SftpRequestMessage<T>>
        extends SftpMessagePreparator<T> {

    protected SftpRequestMessagePreparator(
            Chooser chooser, T message, SftpPacketTypeConstant packetType) {
        super(chooser, message, packetType);
    }

    @Override
    public void prepareMessageSpecificContents() {
        // TODO: Get valid request ID
        getObject().setRequestId(0);
        prepareRequestSpecificContents();
    }

    protected abstract void prepareRequestSpecificContents();
}
