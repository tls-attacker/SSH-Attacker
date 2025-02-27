/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.message.request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestWithPathMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.handler.request.SftpV4RequestStatMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

/** In SFTP V4 flags field was added */
public class SftpV4RequestStatMessage extends SftpRequestWithPathMessage<SftpV4RequestStatMessage> {

    private ModifiableInteger flags;

    public SftpV4RequestStatMessage() {
        super();
    }

    public SftpV4RequestStatMessage(SftpV4RequestStatMessage other) {
        super(other);
        flags = other.flags != null ? other.flags.createCopy() : null;
    }

    @Override
    public SftpV4RequestStatMessage createCopy() {
        return new SftpV4RequestStatMessage(this);
    }

    public ModifiableInteger getFlags() {
        return flags;
    }

    public void setFlags(ModifiableInteger flags) {
        this.flags = flags;
    }

    public void setFlags(int flags) {
        this.flags = ModifiableVariableFactory.safelySetValue(this.flags, flags);
    }

    public void setFlags(SftpFileAttributeFlag... flags) {
        setFlags(SftpFileAttributeFlag.flagsToInt(flags));
    }

    public void clearFlags() {
        flags = null;
    }

    public static final SftpV4RequestStatMessageHandler HANDLER =
            new SftpV4RequestStatMessageHandler();

    @Override
    public SftpV4RequestStatMessageHandler getHandler() {
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
        SftpV4RequestStatMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpV4RequestStatMessageHandler.SERIALIZER.serialize(this);
    }
}
