/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.HashAlgorithm;
import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCheckFileNameMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.List;

public class SftpRequestCheckFileNameMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestCheckFileNameMessage> {

    public SftpRequestCheckFileNameMessagePreparator() {
        super(SftpExtension.CHECK_FILE_NAME);
    }

    @Override
    public void prepareRequestExtendedSpecificContents(
            SftpRequestCheckFileNameMessage object, Chooser chooser) {
        object.setSoftlyPath("/etc/passwd", true, chooser.getConfig());

        object.setSoftlyHashAlgorithms(
                List.of(HashAlgorithm.MD5, HashAlgorithm.SHA_1), true, chooser.getConfig());

        object.setSoftlyStartOffset(0);

        object.setSoftlyLength(100000); // 0 for all data
        object.setSoftlyBlockSize(512); // Should be >= 256
    }
}
