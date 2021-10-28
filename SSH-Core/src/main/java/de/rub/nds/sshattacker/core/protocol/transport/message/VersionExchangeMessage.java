/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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

public class VersionExchangeMessage extends ProtocolMessage<VersionExchangeMessage> {

    private ModifiableString version;
    private ModifiableString comment;

    public VersionExchangeMessage() {
        super();
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

    public ModifiableString getComment() {
        return comment;
    }

    public void setComment(ModifiableString comment) {
        this.comment = comment;
    }

    public void setComment(String comment) {
        this.comment = ModifiableVariableFactory.safelySetValue(this.comment, comment);
    }

    public String getIdentification() {
        if (this.comment.getValue().isEmpty()) return this.version.getValue();
        return this.version.getValue()
                + CharConstants.VERSION_COMMENT_SEPARATOR
                + this.comment.getValue();
    }

    @Override
    public VersionExchangeMessageHandler getHandler(SshContext context) {
        return new VersionExchangeMessageHandler(context, this);
    }

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }
}
