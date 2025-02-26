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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestSubsystemMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class ChannelRequestSubsystemMessage
        extends ChannelRequestMessage<ChannelRequestSubsystemMessage> implements HasSentHandler {

    private ModifiableInteger subsystemNameLength;
    private ModifiableString subsystemName;

    public ChannelRequestSubsystemMessage() {
        super();
    }

    public ChannelRequestSubsystemMessage(ChannelRequestSubsystemMessage other) {
        super(other);
        subsystemNameLength =
                other.subsystemNameLength != null ? other.subsystemNameLength.createCopy() : null;
        subsystemName = other.subsystemName != null ? other.subsystemName.createCopy() : null;
    }

    @Override
    public ChannelRequestSubsystemMessage createCopy() {
        return new ChannelRequestSubsystemMessage(this);
    }

    public ModifiableInteger getSubsystemNameLength() {
        return subsystemNameLength;
    }

    public void setSubsystemNameLength(ModifiableInteger subsystemNameLength) {
        this.subsystemNameLength = subsystemNameLength;
    }

    public void setSubsystemNameLength(int subsystemNameLength) {
        this.subsystemNameLength =
                ModifiableVariableFactory.safelySetValue(
                        this.subsystemNameLength, subsystemNameLength);
    }

    public ModifiableString getSubsystemName() {
        return subsystemName;
    }

    public void setSubsystemName(ModifiableString subsystemName) {
        this.subsystemName = subsystemName;
    }

    public void setSubsystemName(String subsystemName) {
        this.subsystemName =
                ModifiableVariableFactory.safelySetValue(this.subsystemName, subsystemName);
    }

    public void setSubsystemName(ModifiableString subsystemName, boolean adjustLengthField) {
        this.subsystemName = subsystemName;
        if (adjustLengthField) {
            setSubsystemNameLength(
                    this.subsystemName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSubsystemName(String subsystemName, boolean adjustLengthField) {
        this.subsystemName =
                ModifiableVariableFactory.safelySetValue(this.subsystemName, subsystemName);
        if (adjustLengthField) {
            setSubsystemNameLength(
                    this.subsystemName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public static final ChannelRequestSubsystemMessageHandler HANDLER =
            new ChannelRequestSubsystemMessageHandler();

    @Override
    public ChannelRequestSubsystemMessageHandler getHandler() {
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
        ChannelRequestSubsystemMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelRequestSubsystemMessageHandler.SERIALIZER.serialize(this);
    }
}
