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
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCheckFileHandleMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.List;

public class SftpRequestCheckFileHandleMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestCheckFileHandleMessage> {

    public SftpRequestCheckFileHandleMessagePreparator(
            Chooser chooser, SftpRequestCheckFileHandleMessage message) {
        super(chooser, message, SftpExtension.CHECK_FILE_HANDLE);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        getObject().setHandle(chooser.getContext().getSftpManager().getFileHandle(), true);

        if (getObject().getHashAlgorithms() == null) {
            getObject().setHashAlgorithms(List.of(HashAlgorithm.MD5, HashAlgorithm.SHA_1), true);
        }
        if (getObject().getHashAlgorithmsLength() == null) {
            getObject()
                    .setHashAlgorithmsLength(getObject().getHashAlgorithms().getValue().length());
        }

        if (getObject().getStartOffset() == null) {
            getObject().setStartOffset(0);
        }

        if (getObject().getLength() == null) {
            getObject().setLength(100000); // 0 for all data
        }

        if (getObject().getBlockSize() == null) {
            getObject().setBlockSize(512); // Should be >= 256
        }
    }
}
