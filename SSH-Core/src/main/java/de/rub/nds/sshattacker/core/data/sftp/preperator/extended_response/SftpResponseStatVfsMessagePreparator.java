/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response;

import de.rub.nds.sshattacker.core.constants.SftpVfsFlag;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseStatVfsMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseStatVfsMessagePreparator
        extends SftpResponseExtendedMessagePreparator<SftpResponseStatVfsMessage> {

    public SftpResponseStatVfsMessagePreparator(
            Chooser chooser, SftpResponseStatVfsMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareResponseSpecificContents() {
        object.setSoftlyBlockSize(32);
        object.setSoftlyFundamentalBlockSize(32);
        object.setSoftlyCountBlocks(11608687979080L);
        object.setSoftlyFreeBlocks(11608687979080L);
        object.setSoftlyFreeBlocksNonRoot(11608687979080L);
        object.setSoftlyFileInodes(0);
        object.setSoftlyFreeInodes(11608687979080L);
        object.setSoftlyFreeInodesNonRoot(11608687979080L);
        object.setSoftlySystemId(0);
        object.setSoftlyFlags(SftpVfsFlag.SSH_FXE_STATVFS_ST_RDONLY);
        object.setSoftlyMaximumFilenameLength(256);
    }
}
