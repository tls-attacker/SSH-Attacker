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

    protected SftpResponseMessagePreparator(SftpPacketTypeConstant packetType) {
        super(packetType);
    }

    public void prepareMessageSpecificContents(T object, Chooser chooser) {
        // Request identifier should be set by SftpManager in handleRequestMessage()
        object.setRequestId(chooser.getContext().getSftpManager().getNextRequestId());
        prepareResponseSpecificContents(object, chooser);
    }

    protected abstract void prepareResponseSpecificContents(T object, Chooser chooser);
}
