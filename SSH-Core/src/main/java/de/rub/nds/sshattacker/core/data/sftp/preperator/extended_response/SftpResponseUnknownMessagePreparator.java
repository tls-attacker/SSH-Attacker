/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseUnknownMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseUnknownMessagePreparator
        extends SftpResponseExtendedMessagePreparator<SftpResponseUnknownMessage> {

    public SftpResponseUnknownMessagePreparator(
            Chooser chooser, SftpResponseUnknownMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareResponseSpecificContents() {
        object.setSoftlyResponseSpecificData(new byte[100]);
    }
}
