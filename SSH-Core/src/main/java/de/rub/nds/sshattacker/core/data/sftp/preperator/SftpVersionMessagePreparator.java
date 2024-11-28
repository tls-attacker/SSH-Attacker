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
import de.rub.nds.sshattacker.core.data.sftp.message.SftpVersionMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpVersionMessagePreparator extends SftpMessagePreparator<SftpVersionMessage> {

    public SftpVersionMessagePreparator(Chooser chooser, SftpVersionMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_VERSION);
    }

    public void prepareMessageSpecificContents() {

        // Send own server version, but negotiate the version that is the lower if the two
        getObject().setSoftlyVersion(chooser.getSftpServerVersion());
        if (getObject().getExtensions().isEmpty()) {
            getObject().setExtensions(chooser.getSftpServerSupportedExtensions());
        }

        getObject()
                .getExtensions()
                .forEach(
                        extension ->
                                extension
                                        .getHandler(chooser.getContext())
                                        .getPreparator()
                                        .prepare());
    }
}
