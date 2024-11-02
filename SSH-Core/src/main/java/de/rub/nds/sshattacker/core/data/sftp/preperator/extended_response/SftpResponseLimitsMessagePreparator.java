/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseLimitsMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseLimitsMessagePreparator
        extends SftpResponseExtendedMessagePreparator<SftpResponseLimitsMessage> {

    public SftpResponseLimitsMessagePreparator(Chooser chooser, SftpResponseLimitsMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareResponseSpecificContents() {
        if (getObject().getMaximumPacketLength() == null) {
            getObject().setMaximumPacketLength(100000);
        }

        if (getObject().getMaximumReadLength() == null) {
            getObject().setMaximumReadLength(0);
        }

        if (getObject().getMaximumWriteLength() == null) {
            getObject().setMaximumWriteLength(0);
        }

        if (getObject().getMaximumOpenHandles() == null) {
            getObject().setMaximumOpenHandles(1);
        }
    }
}
