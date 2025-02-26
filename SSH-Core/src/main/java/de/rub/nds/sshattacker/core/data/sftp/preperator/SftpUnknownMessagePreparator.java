/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator;

import de.rub.nds.sshattacker.core.data.sftp.SftpMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpUnknownMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpUnknownMessagePreparator extends SftpMessagePreparator<SftpUnknownMessage> {

    public SftpUnknownMessagePreparator() {
        super((byte) 255);
    }

    @Override
    public void prepareMessageSpecificContents(SftpUnknownMessage object, Chooser chooser) {
        object.setPayload(new byte[0]);
    }
}
