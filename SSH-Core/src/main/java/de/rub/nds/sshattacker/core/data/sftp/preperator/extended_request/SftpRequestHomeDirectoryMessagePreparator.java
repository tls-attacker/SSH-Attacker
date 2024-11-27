/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestHomeDirectoryMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestHomeDirectoryMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestHomeDirectoryMessage> {

    public SftpRequestHomeDirectoryMessagePreparator(
            Chooser chooser, SftpRequestHomeDirectoryMessage message) {
        super(chooser, message, SftpExtension.HOME_DIRECTORY);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        if (getObject().getUsername() == null
                || getObject().getUsername().getOriginalValue() == null) {
            getObject().setUsername("ssh-attacker", true);
        }
        if (getObject().getUsernameLength() == null
                || getObject().getUsernameLength().getOriginalValue() == null) {
            getObject().setUsernameLength(getObject().getUsername().getValue().length());
        }
    }
}
