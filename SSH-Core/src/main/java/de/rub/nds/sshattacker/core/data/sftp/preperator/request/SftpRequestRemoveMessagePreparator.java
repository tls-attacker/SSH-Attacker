/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestRemoveMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestRemoveMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestRemoveMessage> {

    public SftpRequestRemoveMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_REMOVE);
    }

    @Override
    public void prepareRequestSpecificContents(SftpRequestRemoveMessage object, Chooser chooser) {
        object.setSoftlyPath("/etc/passwd", true, chooser.getConfig());
    }
}
