/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestSpaceAvailableMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestSpaceAvailableMessage> {

    public SftpRequestSpaceAvailableMessagePreparator() {
        super(SftpExtension.SPACE_AVAILABLE);
    }

    @Override
    public void prepareRequestExtendedSpecificContents(
            SftpRequestSpaceAvailableMessage object, Chooser chooser) {
        object.setPath("/tmp", true);
    }
}
