/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestRealPathMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestRealPathMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestRealPathMessage> {

    public SftpRequestRealPathMessagePreparator(
            Chooser chooser, SftpRequestRealPathMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_REALPATH);
    }

    @Override
    public void prepareRequestSpecificContents() {
        if (getObject().getPath() == null) {
            getObject().setPath("/tmp/../etc/./passwd", true);
        }
        if (getObject().getPathLength() == null) {
            getObject().setPathLength(getObject().getPath().getValue().length());
        }
    }
}
