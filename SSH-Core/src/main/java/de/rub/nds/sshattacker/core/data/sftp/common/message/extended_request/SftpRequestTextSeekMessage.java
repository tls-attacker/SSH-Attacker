/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request.SftpRequestTextSeekMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

/** This extended request is only available from version 4 onwards */
public class SftpRequestTextSeekMessage
        extends SftpRequestExtendedWithHandleMessage<SftpRequestTextSeekMessage> {
    private ModifiableLong lineNumber;

    public SftpRequestTextSeekMessage() {
        super();
    }

    public SftpRequestTextSeekMessage(int handleIndex) {
        super();
        configHandleIndex = handleIndex;
    }

    public SftpRequestTextSeekMessage(SftpRequestTextSeekMessage other) {
        super(other);
        lineNumber = other.lineNumber != null ? other.lineNumber.createCopy() : null;
    }

    @Override
    public SftpRequestTextSeekMessage createCopy() {
        return new SftpRequestTextSeekMessage(this);
    }

    public ModifiableLong getLineNumber() {
        return lineNumber;
    }

    public void setLineNumber(ModifiableLong lineNumber) {
        this.lineNumber = lineNumber;
    }

    public void setLineNumber(long lineNumber) {
        this.lineNumber = ModifiableVariableFactory.safelySetValue(this.lineNumber, lineNumber);
    }

    public static final SftpRequestTextSeekMessageHandler HANDLER =
            new SftpRequestTextSeekMessageHandler();

    @Override
    public SftpRequestTextSeekMessageHandler getHandler() {
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
        SftpRequestTextSeekMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestTextSeekMessageHandler.SERIALIZER.serialize(this);
    }
}
