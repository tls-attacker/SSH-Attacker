/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.preperator.request;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.request.SftpRequestMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestFileSetStatMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpV4RequestFileSetStatMessagePreparator
        extends SftpRequestMessagePreparator<SftpV4RequestFileSetStatMessage> {

    public SftpV4RequestFileSetStatMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_FSETSTAT);
    }

    @Override
    public void prepareRequestSpecificContents(
            SftpV4RequestFileSetStatMessage object, Chooser chooser) {
        object.setHandle(chooser.getContext().getSftpManager().getFileOrDirectoryHandle(), true);

        object.getAttributes().prepare(chooser);
    }
}
