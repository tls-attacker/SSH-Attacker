/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestExpandPathMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestExpandPathMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestExpandPathMessage> {

    public SftpRequestExpandPathMessagePreparator() {
        super(SftpExtension.EXPAND_PATH);
    }

    @Override
    public void prepareRequestExtendedSpecificContents(
            SftpRequestExpandPathMessage object, Chooser chooser) {
        object.setPath("~/etc/passwd", true);
    }
}
