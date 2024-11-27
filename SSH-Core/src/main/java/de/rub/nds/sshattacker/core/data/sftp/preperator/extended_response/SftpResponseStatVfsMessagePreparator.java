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
        if (getObject().getBlockSize() == null || getObject().getBlockSize().getOriginalValue() == null) {
            getObject().setBlockSize(32);
        }
        if (getObject().getFundamentalBlockSize() == null || getObject().getFundamentalBlockSize().getOriginalValue() == null) {
            getObject().setFundamentalBlockSize(32);
        }
        if (getObject().getCountBlocks() == null || getObject().getCountBlocks().getOriginalValue() == null) {
            getObject().setCountBlocks(11608687979080L);
        }
        if (getObject().getFreeBlocks() == null || getObject().getFreeBlocks().getOriginalValue() == null) {
            getObject().setFreeBlocks(11608687979080L);
        }
        if (getObject().getFreeBlocksNonRoot() == null || getObject().getFreeBlocksNonRoot().getOriginalValue() == null) {
            getObject().setFreeBlocksNonRoot(11608687979080L);
        }
        if (getObject().getFileInodes() == null || getObject().getFileInodes().getOriginalValue() == null) {
            getObject().setFileInodes(0);
        }
        if (getObject().getFreeInodes() == null || getObject().getFreeInodes().getOriginalValue() == null) {
            getObject().setFreeInodes(11608687979080L);
        }
        if (getObject().getFreeInodesNonRoot() == null || getObject().getFreeInodesNonRoot().getOriginalValue() == null) {
            getObject().setFreeInodesNonRoot(11608687979080L);
        }
        if (getObject().getSystemId() == null || getObject().getSystemId().getOriginalValue() == null) {
            getObject().setSystemId(0);
        }
        if (getObject().getFlags() == null || getObject().getFlags().getOriginalValue() == null) {
            getObject().setFlags(SftpVfsFlag.SSH_FXE_STATVFS_ST_RDONLY);
        }
        if (getObject().getMaximumFilenameLength() == null || getObject().getMaximumFilenameLength().getOriginalValue() == null) {
            getObject().setMaximumFilenameLength(256);
        }
    }
}
