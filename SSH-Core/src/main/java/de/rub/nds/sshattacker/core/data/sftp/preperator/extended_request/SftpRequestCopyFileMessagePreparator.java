/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCopyFileMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestCopyFileMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestCopyFileMessage> {

    public SftpRequestCopyFileMessagePreparator(
            Chooser chooser, SftpRequestCopyFileMessage message) {
        super(chooser, message, SftpExtension.COPY_FILE);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        if (getObject().getPath() == null || getObject().getPath().getOriginalValue() == null) {
            getObject().setPath("/etc/passwd", true);
        }
        if (getObject().getPathLength() == null || getObject().getPathLength().getOriginalValue() == null) {
            getObject().setPathLength(getObject().getPath().getValue().length());
        }

        if (getObject().getDestinationPath() == null || getObject().getDestinationPath().getOriginalValue() == null) {
            getObject().setDestinationPath("/tmp/passwd", true);
        }
        if (getObject().getDestinationPathLength() == null || getObject().getDestinationPathLength().getOriginalValue() == null) {
            getObject()
                    .setDestinationPathLength(getObject().getDestinationPath().getValue().length());
        }

        if (getObject().getOverwriteDestination() == null || getObject().getOverwriteDestination().getOriginalValue() == null) {
            getObject().setOverwriteDestination(true);
        }
    }
}
