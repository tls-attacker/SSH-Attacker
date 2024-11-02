/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCopyDataMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestCopyDataMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestCopyDataMessage> {

    public SftpRequestCopyDataMessagePreparator(
            Chooser chooser, SftpRequestCopyDataMessage message) {
        super(chooser, message, SftpExtension.COPY_DATA);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        if (getObject().getHandle() == null) {
            // TODO Get valid Handle
            getObject().setHandle(new byte[100], true);
        }
        if (getObject().getHandleLength() == null) {
            getObject().setHandleLength(getObject().getHandle().getValue().length);
        }

        if (getObject().getReadFromOffset() == null) {
            getObject().setReadFromOffset(0);
        }

        if (getObject().getReadDataLength() == null) {
            getObject().setReadDataLength(1000000);
        }

        if (getObject().getWriteToHandle() == null) {
            // TODO Get valid WriteToHandle
            getObject().setWriteToHandle(new byte[100], true);
        }
        if (getObject().getWriteToHandleLength() == null) {
            getObject().setWriteToHandleLength(getObject().getWriteToHandle().getValue().length);
        }

        if (getObject().getWriteToOffset() == null) {
            getObject().setWriteToOffset(0);
        }
    }
}
