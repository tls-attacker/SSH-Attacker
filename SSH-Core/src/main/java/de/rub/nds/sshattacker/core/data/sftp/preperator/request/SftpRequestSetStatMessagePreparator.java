/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileAttributes;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestSetStatMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestSetStatMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestSetStatMessage> {

    public SftpRequestSetStatMessagePreparator(Chooser chooser, SftpRequestSetStatMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_SETSTAT);
    }

    @Override
    public void prepareRequestSpecificContents() {
        if (getObject().getPath() == null) {
            getObject().setPath("/tmp/ssh-attacker", true);
        }
        if (getObject().getPathLength() == null) {
            getObject().setPathLength(getObject().getPath().getValue().length());
        }

        if (getObject().getAttributes() == null) {
            getObject().setAttributes(new SftpFileAttributes());
        }
        getObject().getAttributes().getHandler(chooser.getContext()).getPreparator().prepare();
    }
}
