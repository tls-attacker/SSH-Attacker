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
import de.rub.nds.sshattacker.core.data.sftp.message.SftpInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpInitMessagePreparator extends SftpMessagePreparator<SftpInitMessage> {

    public SftpInitMessagePreparator(Chooser chooser, SftpInitMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_INIT);
    }

    public void prepareMessageSpecificContents() {
        getObject().setSoftlyVersion(chooser.getSftpClientVersion());
        if (getObject().getExtensions().isEmpty()) {
            // Only load default extensions if none are set in the message
            if (chooser.getSftpClientVersion() == 3) {
                // Only Clients with protocol version 3 should send supported extensions,
                // to stay compatible with servers that use protocol version 1 or 2
                getObject().setExtensions(chooser.getSftpClientSupportedExtensions());
            }
        } else {
            if (chooser.getSftpClientVersion() != 3
                    && chooser.getConfig().getRespectSftpNegotiatedVersion()) {
                getObject().getExtensions().clear();
            }
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
