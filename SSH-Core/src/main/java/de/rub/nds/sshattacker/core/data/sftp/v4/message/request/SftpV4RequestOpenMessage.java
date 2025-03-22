/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.message.request;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.SftpFileOpenFlag;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestWithPathMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.handler.request.SftpV4RequestOpenMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.holder.SftpV4FileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.List;

public class SftpV4RequestOpenMessage extends SftpRequestWithPathMessage<SftpV4RequestOpenMessage> {

    // path is the filename

    // TODO: SFTPv5 adds desired-access bitmask and attribute field
    private ModifiableInteger openFlags;

    @HoldsModifiableVariable private SftpV4FileAttributes attributes = new SftpV4FileAttributes();

    public SftpV4RequestOpenMessage() {
        super();
    }

    public SftpV4RequestOpenMessage(SftpV4RequestOpenMessage other) {
        super(other);
        openFlags = other.openFlags != null ? other.openFlags.createCopy() : null;
        attributes = other.attributes != null ? other.attributes.createCopy() : null;
    }

    @Override
    public SftpV4RequestOpenMessage createCopy() {
        return new SftpV4RequestOpenMessage(this);
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

    public void setOpenFlags(SftpFileOpenFlag... fileOpenFlags) {
        setOpenFlags(SftpFileOpenFlag.flagsToInt(fileOpenFlags));
    }

    public SftpV4FileAttributes getAttributes() {
        return attributes;
    }

    public void setAttributes(SftpV4FileAttributes attributes) {
        this.attributes = attributes;
    }

    public static final SftpV4RequestOpenMessageHandler HANDLER =
            new SftpV4RequestOpenMessageHandler();

    @Override
    public SftpV4RequestOpenMessageHandler getHandler() {
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
        SftpV4RequestOpenMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpV4RequestOpenMessageHandler.SERIALIZER.serialize(this);
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
