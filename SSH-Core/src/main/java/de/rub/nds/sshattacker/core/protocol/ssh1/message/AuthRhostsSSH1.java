/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.AuthRhostsHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.AuthRhostsParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.AuthRhostsPreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.AuthRhostsSerializier;
import java.io.InputStream;

public class AuthRhostsSSH1 extends SshMessage<AuthRhostsSSH1> {

    private ModifiableString clientside_username;

    public ModifiableString getClientside_username() {
        return clientside_username;
    }

    public void setClientside_username(ModifiableString clientside_username) {
        this.clientside_username = clientside_username;
    }

    public void setClientside_username(String clientUsername) {
        this.clientside_username =
                ModifiableVariableFactory.safelySetValue(this.clientside_username, clientUsername);
    }

    @Override
    public AuthRhostsHandler getHandler(SshContext context) {
        return new AuthRhostsHandler(context);
    }

    @Override
    public SshMessageParser<AuthRhostsSSH1> getParser(SshContext context, InputStream stream) {
        return new AuthRhostsParser(context, stream);
    }

    @Override
    public SshMessagePreparator<AuthRhostsSSH1> getPreparator(SshContext context) {
        return new AuthRhostsPreparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<AuthRhostsSSH1> getSerializer(SshContext context) {
        return new AuthRhostsSerializier(this);
    }

    @Override
    public String toShortString() {
        return "AUTH_RHOSTS";
    }
}
