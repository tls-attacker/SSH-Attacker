/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_response;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.sshattacker.core.constants.SftpVfsFlag;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_response.SftpResponseStatVfsMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseStatVfsMessage extends SftpResponseMessage<SftpResponseStatVfsMessage> {

    private ModifiableLong blockSize;
    private ModifiableLong fundamentalBlockSize;
    private ModifiableLong countBlocks;
    private ModifiableLong freeBlocks;
    private ModifiableLong freeBlocksNonRoot;
    private ModifiableLong fileInodes;
    private ModifiableLong freeInodes;
    private ModifiableLong freeInodesNonRoot;
    private ModifiableLong systemId;
    private ModifiableLong flags;
    private ModifiableLong maximumFilenameLength;

    public SftpResponseStatVfsMessage() {
        super();
    }

    public SftpResponseStatVfsMessage(SftpResponseStatVfsMessage other) {
        super(other);
        blockSize = other.blockSize != null ? other.blockSize.createCopy() : null;
        fundamentalBlockSize =
                other.fundamentalBlockSize != null ? other.fundamentalBlockSize.createCopy() : null;
        countBlocks = other.countBlocks != null ? other.countBlocks.createCopy() : null;
        freeBlocks = other.freeBlocks != null ? other.freeBlocks.createCopy() : null;
        freeBlocksNonRoot =
                other.freeBlocksNonRoot != null ? other.freeBlocksNonRoot.createCopy() : null;
        fileInodes = other.fileInodes != null ? other.fileInodes.createCopy() : null;
        freeInodes = other.freeInodes != null ? other.freeInodes.createCopy() : null;
        freeInodesNonRoot =
                other.freeInodesNonRoot != null ? other.freeInodesNonRoot.createCopy() : null;
        systemId = other.systemId != null ? other.systemId.createCopy() : null;
        flags = other.flags != null ? other.flags.createCopy() : null;
        maximumFilenameLength =
                other.maximumFilenameLength != null
                        ? other.maximumFilenameLength.createCopy()
                        : null;
    }

    @Override
    public SftpResponseStatVfsMessage createCopy() {
        return new SftpResponseStatVfsMessage(this);
    }

    public ModifiableLong getBlockSize() {
        return blockSize;
    }

    public void setBlockSize(ModifiableLong blockSize) {
        this.blockSize = blockSize;
    }

    public void setBlockSize(long blockSize) {
        this.blockSize = ModifiableVariableFactory.safelySetValue(this.blockSize, blockSize);
    }

    public void setSoftlyBlockSize(long blockSize) {
        if (this.blockSize == null || this.blockSize.getOriginalValue() == null) {
            this.blockSize = ModifiableVariableFactory.safelySetValue(this.blockSize, blockSize);
        }
    }

    public ModifiableLong getFundamentalBlockSize() {
        return fundamentalBlockSize;
    }

    public void setFundamentalBlockSize(ModifiableLong fundamentalBlockSize) {
        this.fundamentalBlockSize = fundamentalBlockSize;
    }

    public void setFundamentalBlockSize(long fundamentalBlockSize) {
        this.fundamentalBlockSize =
                ModifiableVariableFactory.safelySetValue(
                        this.fundamentalBlockSize, fundamentalBlockSize);
    }

    public void setSoftlyFundamentalBlockSize(long fundamentalBlockSize) {
        if (this.fundamentalBlockSize == null
                || this.fundamentalBlockSize.getOriginalValue() == null) {
            this.fundamentalBlockSize =
                    ModifiableVariableFactory.safelySetValue(
                            this.fundamentalBlockSize, fundamentalBlockSize);
        }
    }

    public ModifiableLong getCountBlocks() {
        return countBlocks;
    }

    public void setCountBlocks(ModifiableLong countBlocks) {
        this.countBlocks = countBlocks;
    }

    public void setCountBlocks(long countBlocks) {
        this.countBlocks = ModifiableVariableFactory.safelySetValue(this.countBlocks, countBlocks);
    }

    public void setSoftlyCountBlocks(long countBlocks) {
        if (this.countBlocks == null || this.countBlocks.getOriginalValue() == null) {
            this.countBlocks =
                    ModifiableVariableFactory.safelySetValue(this.countBlocks, countBlocks);
        }
    }

    public ModifiableLong getFreeBlocks() {
        return freeBlocks;
    }

    public void setFreeBlocks(ModifiableLong freeBlocks) {
        this.freeBlocks = freeBlocks;
    }

    public void setFreeBlocks(long freeBlocks) {
        this.freeBlocks = ModifiableVariableFactory.safelySetValue(this.freeBlocks, freeBlocks);
    }

    public void setSoftlyFreeBlocks(long freeBlocks) {
        if (this.freeBlocks == null || this.freeBlocks.getOriginalValue() == null) {
            this.freeBlocks = ModifiableVariableFactory.safelySetValue(this.freeBlocks, freeBlocks);
        }
    }

    public ModifiableLong getFreeBlocksNonRoot() {
        return freeBlocksNonRoot;
    }

    public void setFreeBlocksNonRoot(ModifiableLong freeBlocksNonRoot) {
        this.freeBlocksNonRoot = freeBlocksNonRoot;
    }

    public void setFreeBlocksNonRoot(long freeBlocksNonRoot) {
        this.freeBlocksNonRoot =
                ModifiableVariableFactory.safelySetValue(this.freeBlocksNonRoot, freeBlocksNonRoot);
    }

    public void setSoftlyFreeBlocksNonRoot(long freeBlocksNonRoot) {
        if (this.freeBlocksNonRoot == null || this.freeBlocksNonRoot.getOriginalValue() == null) {
            this.freeBlocksNonRoot =
                    ModifiableVariableFactory.safelySetValue(
                            this.freeBlocksNonRoot, freeBlocksNonRoot);
        }
    }

    public ModifiableLong getFileInodes() {
        return fileInodes;
    }

    public void setFileInodes(ModifiableLong fileInodes) {
        this.fileInodes = fileInodes;
    }

    public void setFileInodes(long fileInodes) {
        this.fileInodes = ModifiableVariableFactory.safelySetValue(this.fileInodes, fileInodes);
    }

    public void setSoftlyFileInodes(long fileInodes) {
        if (this.fileInodes == null || this.fileInodes.getOriginalValue() == null) {
            this.fileInodes = ModifiableVariableFactory.safelySetValue(this.fileInodes, fileInodes);
        }
    }

    public ModifiableLong getFreeInodes() {
        return freeInodes;
    }

    public void setFreeInodes(ModifiableLong freeInodes) {
        this.freeInodes = freeInodes;
    }

    public void setFreeInodes(long freeInodes) {
        this.freeInodes = ModifiableVariableFactory.safelySetValue(this.freeInodes, freeInodes);
    }

    public void setSoftlyFreeInodes(long freeInodes) {
        if (this.freeInodes == null || this.freeInodes.getOriginalValue() == null) {
            this.freeInodes = ModifiableVariableFactory.safelySetValue(this.freeInodes, freeInodes);
        }
    }

    public ModifiableLong getFreeInodesNonRoot() {
        return freeInodesNonRoot;
    }

    public void setFreeInodesNonRoot(ModifiableLong freeInodesNonRoot) {
        this.freeInodesNonRoot = freeInodesNonRoot;
    }

    public void setFreeInodesNonRoot(long freeInodesNonRoot) {
        this.freeInodesNonRoot =
                ModifiableVariableFactory.safelySetValue(this.freeInodesNonRoot, freeInodesNonRoot);
    }

    public void setSoftlyFreeInodesNonRoot(long freeInodesNonRoot) {
        if (this.freeInodesNonRoot == null || this.freeInodesNonRoot.getOriginalValue() == null) {
            this.freeInodesNonRoot =
                    ModifiableVariableFactory.safelySetValue(
                            this.freeInodesNonRoot, freeInodesNonRoot);
        }
    }

    public ModifiableLong getSystemId() {
        return systemId;
    }

    public void setSystemId(ModifiableLong systemId) {
        this.systemId = systemId;
    }

    public void setSystemId(long systemId) {
        this.systemId = ModifiableVariableFactory.safelySetValue(this.systemId, systemId);
    }

    public void setSoftlySystemId(long systemId) {
        if (this.systemId == null || this.systemId.getOriginalValue() == null) {
            this.systemId = ModifiableVariableFactory.safelySetValue(this.systemId, systemId);
        }
    }

    public ModifiableLong getFlags() {
        return flags;
    }

    public void setFlags(ModifiableLong flags) {
        this.flags = flags;
    }

    public void setFlags(long flags) {
        this.flags = ModifiableVariableFactory.safelySetValue(this.flags, flags);
    }

    public void setSoftlyFlags(long flags) {
        if (this.flags == null || this.flags.getOriginalValue() == null) {
            this.flags = ModifiableVariableFactory.safelySetValue(this.flags, flags);
        }
    }

    public void setFlags(SftpVfsFlag... vfsFlags) {
        setFlags(SftpVfsFlag.flagsToLong(vfsFlags));
    }

    public void setSoftlyFlags(SftpVfsFlag... vfsFlags) {
        setSoftlyFlags(SftpVfsFlag.flagsToLong(vfsFlags));
    }

    public ModifiableLong getMaximumFilenameLength() {
        return maximumFilenameLength;
    }

    public void setMaximumFilenameLength(ModifiableLong maximumFilenameLength) {
        this.maximumFilenameLength = maximumFilenameLength;
    }

    public void setMaximumFilenameLength(long maximumFilenameLength) {
        this.maximumFilenameLength =
                ModifiableVariableFactory.safelySetValue(
                        this.maximumFilenameLength, maximumFilenameLength);
    }

    public void setSoftlyMaximumFilenameLength(long maximumFilenameLength) {
        if (this.maximumFilenameLength == null
                || this.maximumFilenameLength.getOriginalValue() == null) {
            this.maximumFilenameLength =
                    ModifiableVariableFactory.safelySetValue(
                            this.maximumFilenameLength, maximumFilenameLength);
        }
    }

    @Override
    public SftpResponseStatVfsMessageHandler getHandler(SshContext context) {
        return new SftpResponseStatVfsMessageHandler(context, this);
    }
}
