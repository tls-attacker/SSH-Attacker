/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestFileSetStatMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestFileSetStatMessagePreparator
        extends SftpRequestMessagePreparator<SftpRequestFileSetStatMessage> {

    public SftpRequestFileSetStatMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_FSETSTAT);
    }

    @Override
    public void prepareRequestSpecificContents(
            SftpRequestFileSetStatMessage object, Chooser chooser) {
        object.setHandle(
                chooser.getContext()
                        .getSftpManager()
                        .getFileOrDirectoryHandle(object.getConfigHandleIndex()),
                true);

        object.getAttributes().prepare(chooser);
    }
}
