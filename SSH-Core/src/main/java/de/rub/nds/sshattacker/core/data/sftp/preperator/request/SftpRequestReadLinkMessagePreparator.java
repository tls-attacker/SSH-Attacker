/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestReadLinkMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestReadLinkMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestReadLinkMessage> {

    public SftpRequestReadLinkMessagePreparator(
            Chooser chooser, SftpRequestReadLinkMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_READLINK);
    }

    @Override
    public void prepareRequestSpecificContents() {
        if (getObject().getPath() == null || getObject().getPath().getOriginalValue() == null) {
            getObject().setPath("/bin/python3", true);
        }
        if (getObject().getPathLength() == null
                || getObject().getPathLength().getOriginalValue() == null) {
            getObject().setPathLength(getObject().getPath().getValue().length());
        }
    }
}
