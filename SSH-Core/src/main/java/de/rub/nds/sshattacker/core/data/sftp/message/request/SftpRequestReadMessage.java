/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestReadMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestReadMessage extends SftpRequestWithHandleMessage<SftpRequestReadMessage> {

    private ModifiableLong offset;
    private ModifiableInteger length;

    public SftpRequestReadMessage() {
        super();
    }

    public SftpRequestReadMessage(SftpRequestReadMessage other) {
        super(other);
        offset = other.offset != null ? other.offset.createCopy() : null;
        length = other.length != null ? other.length.createCopy() : null;
    }

    @Override
    public SftpRequestReadMessage createCopy() {
        return new SftpRequestReadMessage(this);
    }

    public ModifiableLong getOffset() {
        return offset;
    }

    public void setOffset(ModifiableLong offset) {
        this.offset = offset;
    }

    public void setOffset(long offset) {
        this.offset = ModifiableVariableFactory.safelySetValue(this.offset, offset);
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public static final SftpRequestReadMessageHandler HANDLER = new SftpRequestReadMessageHandler();

    @Override
    public SftpRequestReadMessageHandler getHandler() {
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
        SftpRequestReadMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestReadMessageHandler.SERIALIZER.serialize(this);
    }
}
