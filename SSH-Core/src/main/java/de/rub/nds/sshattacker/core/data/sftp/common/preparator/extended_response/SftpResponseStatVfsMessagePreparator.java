/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_response;

import de.rub.nds.sshattacker.core.constants.SftpVfsFlag;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseStatVfsMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseStatVfsMessagePreparator
        extends SftpResponseExtendedMessagePreparator<SftpResponseStatVfsMessage> {

    @Override
    protected void prepareResponseSpecificContents(
            SftpResponseStatVfsMessage object, Chooser chooser) {
        object.setBlockSize(32);
        object.setFundamentalBlockSize(32);
        object.setCountBlocks(11608687979080L);
        object.setFreeBlocks(11608687979080L);
        object.setFreeBlocksNonRoot(11608687979080L);
        object.setFileInodes(0);
        object.setFreeInodes(11608687979080L);
        object.setFreeInodesNonRoot(11608687979080L);
        object.setSystemId(0);
        object.setFlags(SftpVfsFlag.SSH_FXE_STATVFS_ST_RDONLY);
        object.setMaximumFilenameLength(256);
    }
}
