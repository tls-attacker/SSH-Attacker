/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseSpaceAvailableMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseSpaceAvailableMessagePreparator
        extends SftpResponseExtendedMessagePreparator<SftpResponseSpaceAvailableMessage> {

    public SftpResponseSpaceAvailableMessagePreparator(
            Chooser chooser, SftpResponseSpaceAvailableMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareResponseSpecificContents() {
        object.setSoftlyBytesOnDevice(10000000001L);

        object.setSoftlyUnusedBytesOnDevice(10);

        object.setSoftlyBytesAvailableToUser(100);

        object.setSoftlyUnusedBytesAvailableToUser(10);

        object.setSoftlyBytesPerAllocationUnit(0);
    }
}
