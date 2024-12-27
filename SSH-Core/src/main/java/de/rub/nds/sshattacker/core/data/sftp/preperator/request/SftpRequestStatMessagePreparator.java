/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestStatMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestStatMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestStatMessage> {

    public SftpRequestStatMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_STAT);
    }

    @Override
    public void prepareRequestSpecificContents(SftpRequestStatMessage object, Chooser chooser) {
        object.setSoftlyPath("/etc/passwd", true, chooser.getConfig());

        if (chooser.getSftpNegotiatedVersion() > 3
                || !chooser.getConfig().getRespectSftpNegotiatedVersion()) {
            object.setSoftlyFlags(SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE);
        } else {
            object.clearFlags();
        }
    }
}
