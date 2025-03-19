/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestHomeDirectoryMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestHomeDirectoryMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestHomeDirectoryMessage> {

    public SftpRequestHomeDirectoryMessagePreparator() {
        super(SftpExtension.HOME_DIRECTORY);
    }

    @Override
    public void prepareRequestExtendedSpecificContents(
            SftpRequestHomeDirectoryMessage object, Chooser chooser) {
        object.setUsername("ssh-attacker", true);
    }
}
