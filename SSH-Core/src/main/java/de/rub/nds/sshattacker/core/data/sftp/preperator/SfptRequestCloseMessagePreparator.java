/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.SfptRequestCloseMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SfptRequestCloseMessagePreparator
        extends SftpRequestMessagePreparator<SfptRequestCloseMessage> {

    public SfptRequestCloseMessagePreparator(Chooser chooser, SfptRequestCloseMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_CLOSE);
    }

    public void prepareRequestSpecificContents() {
        if (getObject().getHandle() == null) {
            // TODO Set valid handler
            getObject().setHandle(new byte[100], true);
        }
        if (getObject().getHandleLength() == null) {
            getObject().setHandleLength(getObject().getHandle().getValue().length);
        }
    }
}
