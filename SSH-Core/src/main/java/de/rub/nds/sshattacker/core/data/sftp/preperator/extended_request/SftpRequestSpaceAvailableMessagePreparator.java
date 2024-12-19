/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestSpaceAvailableMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestSpaceAvailableMessage> {

    public SftpRequestSpaceAvailableMessagePreparator(
            Chooser chooser, SftpRequestSpaceAvailableMessage message) {
        super(chooser, message, SftpExtension.SPACE_AVAILABLE);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        object.setSoftlyPath("/tmp", true, config);
    }
}
