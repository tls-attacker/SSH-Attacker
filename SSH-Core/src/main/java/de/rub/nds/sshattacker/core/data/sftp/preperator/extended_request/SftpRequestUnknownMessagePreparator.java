/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestUnknownMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestUnknownMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestUnknownMessage> {

    public SftpRequestUnknownMessagePreparator(Chooser chooser, SftpRequestUnknownMessage message) {
        super(chooser, message, "hello-from@ssh-attacker.de");
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        getObject().setSoftlyRequestSpecificData(new byte[100]);
    }
}
