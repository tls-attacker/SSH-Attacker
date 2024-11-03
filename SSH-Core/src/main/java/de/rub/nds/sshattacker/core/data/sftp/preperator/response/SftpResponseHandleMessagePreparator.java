/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.response;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseHandleMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseHandleMessagePreparator
        extends SftpResponseMessagePreparator<SftpResponseHandleMessage> {

    public SftpResponseHandleMessagePreparator(Chooser chooser, SftpResponseHandleMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_HANDLE);
    }

    @Override
    public void prepareResponseSpecificContents() {
        if (getObject().getHandle() == null) {
            // Should be set in SftpManager handleRequestMessage()
            getObject().setHandle(new byte[100], true);
        }
        if (getObject().getHandleLength() == null) {
            getObject().setHandleLength(getObject().getHandle().getValue().length);
        }
    }
}
