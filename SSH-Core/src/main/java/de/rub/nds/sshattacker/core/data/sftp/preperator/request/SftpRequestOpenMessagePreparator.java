/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpFileOpenFlag;
import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestOpenMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestOpenMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestOpenMessage> {

    public SftpRequestOpenMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_OPEN);
    }

    @Override
    public void prepareRequestSpecificContents(SftpRequestOpenMessage object, Chooser chooser) {
        object.setPath("/etc/passwd", true);

        object.setOpenFlags(SftpFileOpenFlag.SSH_FXF_READ, SftpFileOpenFlag.SSH_FXF_CREAT);

        object.getAttributes().prepare(chooser);
    }
}
