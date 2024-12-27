/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.response;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseDataMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseDataMessagePreparator
        extends SftpResponseMessagePreparator<SftpResponseDataMessage> {

    public SftpResponseDataMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_DATA);
    }

    @Override
    public void prepareResponseSpecificContents(SftpResponseDataMessage object, Chooser chooser) {
        object.setSoftlyData(new byte[100], true, chooser.getConfig());
    }
}
