/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_request;

import de.rub.nds.sshattacker.core.constants.HashAlgorithm;
import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestCheckFileNameMessage;
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
        object.setPath("/etc/passwd", true);

        object.setHashAlgorithms(List.of(HashAlgorithm.MD5, HashAlgorithm.SHA_1), true);

        object.setStartOffset(0);

        object.setLength(100000); // 0 for all data
        object.setBlockSize(512); // Should be >= 256
    }
}
