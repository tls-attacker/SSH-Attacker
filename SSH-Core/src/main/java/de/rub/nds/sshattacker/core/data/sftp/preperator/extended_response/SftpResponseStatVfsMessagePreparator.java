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
        getObject().setSoftlyBlockSize(32);
        getObject().setSoftlyFundamentalBlockSize(32);
        getObject().setSoftlyCountBlocks(11608687979080L);
        getObject().setSoftlyFreeBlocks(11608687979080L);
        getObject().setSoftlyFreeBlocksNonRoot(11608687979080L);
        getObject().setSoftlyFileInodes(0);
        getObject().setSoftlyFreeInodes(11608687979080L);
        getObject().setSoftlyFreeInodesNonRoot(11608687979080L);
        getObject().setSoftlySystemId(0);
        getObject().setSoftlyFlags(SftpVfsFlag.SSH_FXE_STATVFS_ST_RDONLY);
        getObject().setSoftlyMaximumFilenameLength(256);
    }
}
