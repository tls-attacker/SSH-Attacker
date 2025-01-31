/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.SftpFileOpenFlag;
import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestOpenMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.List;

public class SftpRequestOpenMessage extends SftpRequestWithPathMessage<SftpRequestOpenMessage> {

    // path is the filename

    // TODO: SFTPv5 adds desired-access bitmask and attribute field
    private ModifiableInteger openFlags;

    @HoldsModifiableVariable private SftpFileAttributes attributes = new SftpFileAttributes();

    public SftpRequestOpenMessage() {
        super();
    }

    public SftpRequestOpenMessage(SftpRequestOpenMessage other) {
        super(other);
        openFlags = other.openFlags != null ? other.openFlags.createCopy() : null;
        attributes = other.attributes != null ? other.attributes.createCopy() : null;
    }

    @Override
    public SftpRequestOpenMessage createCopy() {
        return new SftpRequestOpenMessage(this);
    }

    public ModifiableInteger getOpenFlags() {
        return openFlags;
    }

    public void setOpenFlags(ModifiableInteger openFlags) {
        this.openFlags = openFlags;
    }

    public void setOpenFlags(int openFlags) {
        this.openFlags = ModifiableVariableFactory.safelySetValue(this.openFlags, openFlags);
    }

    public void setSoftlyOpenFlags(int openFlags) {
        if (this.openFlags == null || this.openFlags.getOriginalValue() == null) {
            this.openFlags = ModifiableVariableFactory.safelySetValue(this.openFlags, openFlags);
        }
    }

    public void setOpenFlags(SftpFileOpenFlag... fileOpenFlags) {
        setOpenFlags(SftpFileOpenFlag.flagsToInt(fileOpenFlags));
    }

    public void setSoftlyOpenFlags(SftpFileOpenFlag... fileOpenFlags) {
        setSoftlyOpenFlags(SftpFileOpenFlag.flagsToInt(fileOpenFlags));
    }

    public SftpFileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpFileAttributes attributes) {
        this.attributes = attributes;
    }

    public static final SftpRequestOpenMessageHandler HANDLER = new SftpRequestOpenMessageHandler();

    @Override
    public SftpRequestOpenMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestOpenMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestOpenMessageHandler.SERIALIZER.serialize(this);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (attributes != null) {
            holders.addAll(attributes.getAllModifiableVariableHolders());
        }
        return holders;
    }
}
