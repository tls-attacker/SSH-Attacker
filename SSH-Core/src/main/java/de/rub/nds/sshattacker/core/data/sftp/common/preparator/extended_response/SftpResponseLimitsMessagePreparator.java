/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseLimitsMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseLimitsMessagePreparator
        extends SftpResponseExtendedMessagePreparator<SftpResponseLimitsMessage> {

    @Override
    protected void prepareResponseSpecificContents(
            SftpResponseLimitsMessage object, Chooser chooser) {
        object.setMaximumPacketLength(100000);

        object.setMaximumReadLength(0);

        object.setMaximumWriteLength(0);

        object.setMaximumOpenHandles(1);
    }
}
