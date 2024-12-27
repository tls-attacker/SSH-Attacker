/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestFileSyncMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestFileSyncMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestFileSyncMessage> {

    public SftpRequestFileSyncMessagePreparator() {
        super(SftpExtension.F_SYNC_OPENSSH_COM);
    }

    @Override
    public void prepareRequestExtendedSpecificContents(
            SftpRequestFileSyncMessage object, Chooser chooser) {
        object.setSoftlyHandle(
                chooser.getContext().getSftpManager().getFileHandle(), true, chooser.getConfig());
    }
}
