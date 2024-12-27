/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestMakeDirMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestMakeDirMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestMakeDirMessage> {

    public SftpRequestMakeDirMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_MKDIR);
    }

    @Override
    public void prepareRequestSpecificContents(SftpRequestMakeDirMessage object, Chooser chooser) {
        object.setSoftlyPath("/tmp/ssh-attacker/", true, chooser.getConfig());

        object.getAttributes().prepare(chooser);
    }
}
