/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpFileOpenFlag;
import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.request.SftpRequestMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestOpenMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpV4RequestOpenMessagePreparator
        extends SftpRequestMessagePreparator<SftpV4RequestOpenMessage> {

    public SftpV4RequestOpenMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_OPEN);
    }

    @Override
    public void prepareRequestSpecificContents(SftpV4RequestOpenMessage object, Chooser chooser) {
        object.setPath("/etc/passwd", true);

        object.setOpenFlags(SftpFileOpenFlag.SSH_FXF_READ, SftpFileOpenFlag.SSH_FXF_CREAT);

        object.getAttributes().prepare(chooser);
    }
}
