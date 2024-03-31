/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.general.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.handler.DisconnectMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.parser.DisconnectMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.preparator.DisconnectMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.serializer.DisconnectMessageSerializier;
import java.io.InputStream;

public class DisconnectMessageSSH1 extends Ssh1Message<DisconnectMessageSSH1> {

    private ModifiableString disconnectReason;

    public ModifiableString getDisconnectReason() {
        return disconnectReason;
    }

    public void setDisconnectReason(ModifiableString disconnectReason) {
        this.disconnectReason = disconnectReason;
    }

    public void setDisconnectReason(String disconnectReason) {
        this.disconnectReason =
                ModifiableVariableFactory.safelySetValue(this.disconnectReason, disconnectReason);
    }

    @Override
    public DisconnectMessageHandler getHandler(SshContext sshContext) {
        return new DisconnectMessageHandler(sshContext);
    }

    @Override
    public Ssh1MessageParser<DisconnectMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new DisconnectMessageParser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<DisconnectMessageSSH1> getPreparator(SshContext sshContext) {
        return new DisconnectMessagePreparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<DisconnectMessageSSH1> getSerializer(SshContext sshContext) {
        return new DisconnectMessageSerializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_DISCONNECT";
    }
}
