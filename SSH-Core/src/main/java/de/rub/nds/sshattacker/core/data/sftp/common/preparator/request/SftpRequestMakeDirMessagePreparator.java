/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestMakeDirMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestMakeDirMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestMakeDirMessage> {

    public SftpRequestMakeDirMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_MKDIR);
    }

    @Override
    protected void prepareRequestSpecificContents(
            SftpRequestMakeDirMessage object, Chooser chooser) {
        object.setPath("/tmp/ssh-attacker/", true);

        object.getAttributes().prepare(chooser);
    }
}
