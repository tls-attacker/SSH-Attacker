/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestRenameMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestRenameMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestRenameMessage> {

    public SftpRequestRenameMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_RENAME);
    }

    @Override
    public void prepareRequestSpecificContents(SftpRequestRenameMessage object, Chooser chooser) {
        object.setSoftlyPath("/etc/passwd", true, chooser.getConfig());

        object.setSoftlyNewPath("/tmp/passwd-win", true, chooser.getConfig());
    }
}
