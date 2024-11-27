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
        getObject().setHandle(chooser.getContext().getSftpManager().getFileHandle(), true);

        if (getObject().getReadFromOffset() == null
                || getObject().getReadFromOffset().getOriginalValue() == null) {
            getObject().setReadFromOffset(0);
        }

        if (getObject().getReadDataLength() == null
                || getObject().getReadDataLength().getOriginalValue() == null) {
            getObject().setReadDataLength(1000000);
        }

        getObject().setWriteToHandle(chooser.getContext().getSftpManager().getFileHandle(), true);

        if (getObject().getWriteToOffset() == null
                || getObject().getWriteToOffset().getOriginalValue() == null) {
            getObject().setWriteToOffset(0);
        }
    }
}
