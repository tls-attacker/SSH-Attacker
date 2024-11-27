/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestExpandPathMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestExpandPathMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestExpandPathMessage> {

    public SftpRequestExpandPathMessagePreparator(
            Chooser chooser, SftpRequestExpandPathMessage message) {
        super(chooser, message, SftpExtension.EXPAND_PATH);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        if (getObject().getPath() == null || getObject().getPath().getOriginalValue() == null) {
            getObject().setPath("~/.config/passwd", true);
        }
        if (getObject().getPathLength() == null
                || getObject().getPathLength().getOriginalValue() == null) {
            getObject().setPathLength(getObject().getPath().getValue().length());
        }
    }
}
