/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseSpaceAvailableMessagePreparator
        extends SftpResponseExtendedMessagePreparator<SftpResponseSpaceAvailableMessage> {

    @Override
    protected void prepareResponseSpecificContents(
            SftpResponseSpaceAvailableMessage object, Chooser chooser) {
        object.setBytesOnDevice(10000000001L);

        object.setUnusedBytesOnDevice(10);

        object.setBytesAvailableToUser(100);

        object.setUnusedBytesAvailableToUser(10);

        object.setBytesPerAllocationUnit(0);
    }
}
