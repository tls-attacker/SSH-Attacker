/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestSetStatMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestSetStatMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestSetStatMessage> {

    public SftpRequestSetStatMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_SETSTAT);
    }

    @Override
    public void prepareRequestSpecificContents(SftpRequestSetStatMessage object, Chooser chooser) {
        object.setPath("/tmp/ssh-attacker", true);

        object.getAttributes().prepare(chooser);
    }
}
