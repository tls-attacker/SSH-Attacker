/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestMakeTempFolderMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestMakeTempFolderMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestMakeTempFolderMessage> {

    public SftpRequestMakeTempFolderMessagePreparator(
            Chooser chooser, SftpRequestMakeTempFolderMessage message) {
        super(chooser, message, SftpExtension.MAKE_TEMP_FOLDER);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {}
}
