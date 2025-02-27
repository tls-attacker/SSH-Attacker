/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestRemoveDirMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestRemoveDirMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestRemoveDirMessage> {

    public SftpRequestRemoveDirMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_RMDIR);
    }

    public void prepareRequestSpecificContents(
            SftpRequestRemoveDirMessage object, Chooser chooser) {
        object.setPath("/tmp/ssh-attacker", true);
    }
}
