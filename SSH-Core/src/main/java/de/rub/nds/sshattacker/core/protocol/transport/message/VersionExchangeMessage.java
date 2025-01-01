/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.VersionExchangeMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class VersionExchangeMessage extends ProtocolMessage<VersionExchangeMessage> {

    private ModifiableString version;
    private ModifiableString comment;
    private ModifiableString endOfMessageSequence;

    public VersionExchangeMessage() {
        super();
    }

    public VersionExchangeMessage(VersionExchangeMessage other) {
        super(other);
        version = other.version != null ? other.version.createCopy() : null;
        comment = other.comment != null ? other.comment.createCopy() : null;
        endOfMessageSequence =
                other.endOfMessageSequence != null ? other.endOfMessageSequence.createCopy() : null;
    }

    @Override
    public VersionExchangeMessage createCopy() {
        return new VersionExchangeMessage(this);
    }

    public ModifiableString getVersion() {
        return version;
    }

    public void setVersion(ModifiableString version) {
        this.version = version;
    }

    public void setVersion(String version) {
        this.version = ModifiableVariableFactory.safelySetValue(this.version, version);
    }

    public void setSoftlyVersion(String version) {
        if (this.version == null || this.version.getOriginalValue() == null) {
            this.version = ModifiableVariableFactory.safelySetValue(this.version, version);
        }
    }

    public ModifiableString getComment() {
        return comment;
    }

    public void setComment(ModifiableString comment) {
        this.comment = comment;
    }

    public void setComment(String comment) {
        this.comment = ModifiableVariableFactory.safelySetValue(this.comment, comment);
    }

    public void setSoftlyComment(String comment) {
        if (this.comment == null || this.comment.getOriginalValue() == null) {
            this.comment = ModifiableVariableFactory.safelySetValue(this.comment, comment);
        }
    }

    public String getIdentification() {
        if (comment.getValue().isEmpty()) return version.getValue();
        return version.getValue() + CharConstants.VERSION_COMMENT_SEPARATOR + comment.getValue();
    }

    public ModifiableString getEndOfMessageSequence() {
        return endOfMessageSequence;
    }

    public void setEndOfMessageSequence(ModifiableString endOfMessageSequence) {
        this.endOfMessageSequence = endOfMessageSequence;
    }

    public void setEndOfMessageSequence(String endOfMessageSequence) {
        this.endOfMessageSequence =
                ModifiableVariableFactory.safelySetValue(
                        this.endOfMessageSequence, endOfMessageSequence);
    }

    public void setSoftlyEndOfMessageSequence(String endOfMessageSequence) {
        if (this.endOfMessageSequence == null
                || this.endOfMessageSequence.getOriginalValue() == null) {
            this.endOfMessageSequence =
                    ModifiableVariableFactory.safelySetValue(
                            this.endOfMessageSequence, endOfMessageSequence);
        }
    }

    public static final VersionExchangeMessageHandler HANDLER = new VersionExchangeMessageHandler();

    @Override
    public VersionExchangeMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        VersionExchangeMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return VersionExchangeMessageHandler.SERIALIZER.serialize(this);
    }

    @Override
    public String toCompactString() {
        return getClass().getSimpleName();
    }
}
