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
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.AuthPasswordHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.AuthPasswordParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.AuthPasswordPreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.AuthPasswordSerializier;
import java.io.InputStream;

public class AuthPasswordSSH1 extends Ssh1Message<AuthPasswordSSH1> {

    private ModifiableString password;

    public ModifiableString getPassword() {
        return password;
    }

    public void setPassword(ModifiableString password) {
        this.password = password;
    }

    public void setPassword(String password) {
        this.password = ModifiableVariableFactory.safelySetValue(this.password, password);
    }

    @Override
    public AuthPasswordHandler getHandler(SshContext sshContext) {
        return new AuthPasswordHandler(sshContext);
    }

    @Override
    public Ssh1MessageParser<AuthPasswordSSH1> getParser(SshContext context, InputStream stream) {
        return new AuthPasswordParser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<AuthPasswordSSH1> getPreparator(SshContext sshContext) {
        return new AuthPasswordPreparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<AuthPasswordSSH1> getSerializer(SshContext sshContext) {
        return new AuthPasswordSerializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_AUTH_PASSWORD";
    }
}
