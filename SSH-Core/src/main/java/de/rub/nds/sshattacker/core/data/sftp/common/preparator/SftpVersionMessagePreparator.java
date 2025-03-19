/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.message.SftpVersionMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpVersionMessagePreparator extends SftpMessagePreparator<SftpVersionMessage> {

    public SftpVersionMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_VERSION);
    }

    public void prepareMessageSpecificContents(SftpVersionMessage object, Chooser chooser) {
        // Send own server version, but negotiate the version that is the lower if the two
        object.setVersion(chooser.getSftpServerVersion());
        if (object.getExtensions().isEmpty()) {
            // Only load default extensions if none are set in the message
            object.setExtensions(chooser.getSftpServerSupportedExtensions());
        }

        object.getExtensions().forEach(extension -> extension.prepare(chooser));
    }
}
