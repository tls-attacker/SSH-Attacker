/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.AuthRhostsHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.AuthRhostsParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.AuthRhostsPreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.AuthRhostsSerializier;
import java.io.InputStream;

public class AuthRhostsSSH1 extends Ssh1Message<AuthRhostsSSH1> {

    private ModifiableString clientside_username;

    public ModifiableString getClientside_username() {
        return clientside_username;
    }

    public void setClientside_username(ModifiableString clientside_username) {
        this.clientside_username = clientside_username;
    }

    public void setClientside_username(String clientUsername) {
        clientside_username =
                ModifiableVariableFactory.safelySetValue(clientside_username, clientUsername);
    }

    @Override
    public AuthRhostsHandler getHandler(SshContext sshContext) {
        return new AuthRhostsHandler(sshContext);
    }

    @Override
    public Ssh1MessageParser<AuthRhostsSSH1> getParser(SshContext context, InputStream stream) {
        return new AuthRhostsParser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<AuthRhostsSSH1> getPreparator(SshContext sshContext) {
        return new AuthRhostsPreparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<AuthRhostsSSH1> getSerializer(SshContext sshContext) {
        return new AuthRhostsSerializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_AUTH_RHOSTS";
    }
}
