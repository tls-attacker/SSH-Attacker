/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.preparator.request;

import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.request.SftpRequestMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestStatMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpV4RequestStatMessagePreparator
        extends SftpRequestMessagePreparator<SftpV4RequestStatMessage> {

    public SftpV4RequestStatMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_STAT);
    }

    @Override
    public void prepareRequestSpecificContents(SftpV4RequestStatMessage object, Chooser chooser) {
        object.setPath("/etc/passwd", true);

        object.setFlags(SftpFileAttributeFlag.values());
    }
}
