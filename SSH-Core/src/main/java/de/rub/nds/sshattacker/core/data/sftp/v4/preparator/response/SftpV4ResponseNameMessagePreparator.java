/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.preparator.response;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.response.SftpResponseMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.response.SftpV4ResponseNameMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpV4ResponseNameMessagePreparator
        extends SftpResponseMessagePreparator<SftpV4ResponseNameMessage> {

    public SftpV4ResponseNameMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_NAME);
    }

    @Override
    public void prepareResponseSpecificContents(SftpV4ResponseNameMessage object, Chooser chooser) {
        object.setNameEntriesCount(object.getNameEntries().size());

        object.getNameEntries().forEach(nameEntry -> nameEntry.prepare(chooser));
    }
}
