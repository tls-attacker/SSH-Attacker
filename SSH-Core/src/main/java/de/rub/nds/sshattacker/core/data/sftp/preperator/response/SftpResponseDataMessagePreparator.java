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

    public SftpResponseDataMessagePreparator(Chooser chooser, SftpResponseDataMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_DATA);
    }

    @Override
    public void prepareResponseSpecificContents() {
        if (getObject().getData() == null) {
            getObject().setData(new byte[100], true);
        }
        if (getObject().getDataLength() == null) {
            getObject().setDataLength(getObject().getData().getValue().length);
        }
    }
}
