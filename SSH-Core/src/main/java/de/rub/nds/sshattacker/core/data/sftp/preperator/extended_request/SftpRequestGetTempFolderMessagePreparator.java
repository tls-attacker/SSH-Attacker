/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestGetTempFolderMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestGetTempFolderMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestGetTempFolderMessage> {

    public SftpRequestGetTempFolderMessagePreparator(
            Chooser chooser, SftpRequestGetTempFolderMessage message) {
        super(chooser, message, SftpExtension.GET_TEMP_FOLDER);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {}
}
