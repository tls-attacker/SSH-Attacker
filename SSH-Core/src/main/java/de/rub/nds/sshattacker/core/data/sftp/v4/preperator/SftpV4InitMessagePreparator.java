/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.preperator;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.SftpV4InitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpV4InitMessagePreparator extends SftpMessagePreparator<SftpV4InitMessage> {

    public SftpV4InitMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_INIT);
    }

    public void prepareMessageSpecificContents(SftpV4InitMessage object, Chooser chooser) {
        object.setVersion(chooser.getSftpClientVersion());
        object.getExtensions().clear();
    }
}
