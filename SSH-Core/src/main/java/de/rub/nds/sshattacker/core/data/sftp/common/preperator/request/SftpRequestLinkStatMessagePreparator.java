/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestLinkStatMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestLinkStatMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestLinkStatMessage> {

    public SftpRequestLinkStatMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_LSTAT);
    }

    @Override
    public void prepareRequestSpecificContents(SftpRequestLinkStatMessage object, Chooser chooser) {
        object.setPath("/bin/python3", true);
    }
}
