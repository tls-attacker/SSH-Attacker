/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.request.SftpRequestMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestMakeDirMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpV4RequestMakeDirMessagePreparator
        extends SftpRequestMessagePreparator<SftpV4RequestMakeDirMessage> {

    public SftpV4RequestMakeDirMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_MKDIR);
    }

    @Override
    public void prepareRequestSpecificContents(
            SftpV4RequestMakeDirMessage object, Chooser chooser) {
        object.setPath("/tmp/ssh-attacker/", true);

        object.getAttributes().prepare(chooser);
    }
}
