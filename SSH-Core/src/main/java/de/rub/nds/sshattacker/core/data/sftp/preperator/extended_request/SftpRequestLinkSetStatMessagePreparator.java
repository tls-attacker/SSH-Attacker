/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestLinkSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestLinkSetStatMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestLinkSetStatMessage> {

    public SftpRequestLinkSetStatMessagePreparator(
            Chooser chooser, SftpRequestLinkSetStatMessage message) {
        super(chooser, message, SftpExtension.L_SET_STAT);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        if (getObject().getPath() == null || getObject().getPath().getOriginalValue() == null) {
            getObject().setPath("/bin/python3", true);
        }

        if (getObject().getPathLength() == null
                || getObject().getPathLength().getOriginalValue() == null) {
            getObject().setPathLength(getObject().getPath().getValue().length());
        }
        if (getObject().getAttributes() == null) {
            getObject().setAttributes(new SftpFileAttributes());
        }
        getObject().getAttributes().getHandler(chooser.getContext()).getPreparator().prepare();
    }
}
