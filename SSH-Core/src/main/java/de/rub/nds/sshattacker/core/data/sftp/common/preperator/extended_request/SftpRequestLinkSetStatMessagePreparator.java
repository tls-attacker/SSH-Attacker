/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestLinkSetStatMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestLinkSetStatMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestLinkSetStatMessage> {

    public SftpRequestLinkSetStatMessagePreparator() {
        super(SftpExtension.L_SET_STAT);
    }

    @Override
    public void prepareRequestExtendedSpecificContents(
            SftpRequestLinkSetStatMessage object, Chooser chooser) {
        object.setPath("/bin/python3", true);
        object.getAttributes().prepare(chooser);
    }
}
