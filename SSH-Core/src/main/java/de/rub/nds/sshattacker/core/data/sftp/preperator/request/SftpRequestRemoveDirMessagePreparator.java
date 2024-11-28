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
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestRmdirMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestRemoveDirMessagePreparator
        extends SftpMessagePreparator<SftpRequestRmdirMessage> {

    public SftpRequestRemoveDirMessagePreparator(Chooser chooser, SftpRequestRmdirMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_RMDIR);
    }

    public void prepareMessageSpecificContents() {
        getObject().setSoftlyPath("/tmp/ssh-attacker", true, chooser.getConfig());
    }
}
