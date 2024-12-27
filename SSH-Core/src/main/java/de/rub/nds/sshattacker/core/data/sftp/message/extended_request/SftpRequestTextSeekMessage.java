/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestTextSeekMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestTextSeekMessage
        extends SftpRequestExtendedWithHandleMessage<SftpRequestTextSeekMessage> {

    private ModifiableLong lineNumber;

    public SftpRequestTextSeekMessage() {
        super();
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

    public void setSoftlyLineNumber(long lineNumber) {
        if (this.lineNumber == null || this.lineNumber.getOriginalValue() == null) {
            this.lineNumber = ModifiableVariableFactory.safelySetValue(this.lineNumber, lineNumber);
        }
    }

    @Override
    public SftpRequestTextSeekMessageHandler getHandler(SshContext context) {
        return new SftpRequestTextSeekMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestTextSeekMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
