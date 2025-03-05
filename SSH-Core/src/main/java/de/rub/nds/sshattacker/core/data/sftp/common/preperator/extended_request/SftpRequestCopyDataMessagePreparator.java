/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestCopyDataMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestCopyDataMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestCopyDataMessage> {

    public SftpRequestCopyDataMessagePreparator() {
        super(SftpExtension.COPY_DATA);
    }

    @Override
    public void prepareRequestExtendedSpecificContents(
            SftpRequestCopyDataMessage object, Chooser chooser) {
        object.setHandle(
                chooser.getContext().getSftpManager().getFileHandle(object.getConfigHandleIndex()),
                true);

        object.setReadFromOffset(0);

        object.setReadDataLength(1000000);

        object.setWriteToHandle(
                chooser.getContext()
                        .getSftpManager()
                        .getFileHandle(object.getConfigWriteToHandleIndex()),
                true);

        object.setWriteToOffset(0);
    }
}
