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
        super(chooser, message, "");
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        if (getObject().getExtendedRequestName() == null
                || getObject().getExtendedRequestName().getOriginalValue() == null) {
            getObject().setExtendedRequestName("hello-from@ssh-attacker.de");
        }
        if (getObject().getExtendedRequestNameLength() == null
                || getObject().getExtendedRequestNameLength().getOriginalValue() == null) {
            getObject()
                    .setExtendedRequestNameLength(
                            getObject().getExtendedRequestName().getValue().length());
        }

        if (getObject().getRequestSpecificData() == null
                || getObject().getRequestSpecificData().getOriginalValue() == null) {
            getObject().setRequestSpecificData(new byte[100]);
        }
    }
}
