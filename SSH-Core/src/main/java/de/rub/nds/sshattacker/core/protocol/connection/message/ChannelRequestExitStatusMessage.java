/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestExitStatusMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelRequestExitStatusMessage
        extends ChannelRequestMessage<ChannelRequestExitStatusMessage> implements HasSentHandler {

    private ModifiableInteger exitStatus;

    public ChannelRequestExitStatusMessage() {
        super();
    }

    public ChannelRequestExitStatusMessage(ChannelRequestExitStatusMessage other) {
        super(other);
        exitStatus = other.exitStatus != null ? other.exitStatus.createCopy() : null;
    }

    @Override
    public ChannelRequestExitStatusMessage createCopy() {
        return new ChannelRequestExitStatusMessage(this);
    }

    public ModifiableInteger getExitStatus() {
        return exitStatus;
    }

    public void setExitStatus(ModifiableInteger exitStatus) {
        this.exitStatus = exitStatus;
    }

    public void setExitStatus(int exitStatus) {
        this.exitStatus = ModifiableVariableFactory.safelySetValue(this.exitStatus, exitStatus);
    }

    public void setSoftlyExitStatus(int exitStatus) {
        if (this.exitStatus == null || this.exitStatus.getOriginalValue() == null) {
            this.exitStatus = ModifiableVariableFactory.safelySetValue(this.exitStatus, exitStatus);
        }
    }

    public static final ChannelRequestExitStatusMessageHandler HANDLER =
            new ChannelRequestExitStatusMessageHandler();

    @Override
    public ChannelRequestExitStatusMessageHandler getHandler() {
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
        ChannelRequestExitStatusMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelRequestExitStatusMessageHandler.SERIALIZER.serialize(this);
    }
}
