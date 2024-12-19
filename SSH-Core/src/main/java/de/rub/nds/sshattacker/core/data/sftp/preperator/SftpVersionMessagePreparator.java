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
        object.setSoftlyVersion(chooser.getSftpServerVersion());
        if (object.getExtensions().isEmpty()) {
            // Only load default extensions if none are set in the message
            object.setExtensions(chooser.getSftpServerSupportedExtensions());
        }

        object.getExtensions()
                .forEach(
                        extension ->
                                extension
                                        .getHandler(chooser.getContext())
                                        .getPreparator()
                                        .prepare());
    }
}
