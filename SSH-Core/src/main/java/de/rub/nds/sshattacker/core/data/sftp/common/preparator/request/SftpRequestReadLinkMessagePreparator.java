/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestReadLinkMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestReadLinkMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestReadLinkMessage> {

    public SftpRequestReadLinkMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_READLINK);
    }

    @Override
    public void prepareRequestSpecificContents(SftpRequestReadLinkMessage object, Chooser chooser) {
        object.setPath("/bin/python3", true);
    }
}
