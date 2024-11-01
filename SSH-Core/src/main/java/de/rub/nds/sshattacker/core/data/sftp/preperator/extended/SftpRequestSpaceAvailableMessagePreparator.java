/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestSpaceAvailableMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestSpaceAvailableMessage> {

    public SftpRequestSpaceAvailableMessagePreparator(
            Chooser chooser, SftpRequestSpaceAvailableMessage message) {
        super(chooser, message, SftpExtension.SPACE_AVAILABLE);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        if (getObject().getPath() == null) {
            getObject().setPath("/tmp", true);
        }
        if (getObject().getPathLength() == null) {
            getObject().setPathLength(getObject().getPath().getValue().length());
        }
    }
}
