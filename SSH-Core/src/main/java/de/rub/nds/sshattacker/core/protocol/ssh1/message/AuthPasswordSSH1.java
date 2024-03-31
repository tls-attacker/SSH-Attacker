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
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.AuthPasswordHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.AuthPasswordParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.AuthPasswordPreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.AuthPasswordSerializier;
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
    public AuthPasswordHandler getHandler(SshContext context) {
        return new AuthPasswordHandler(context);
    }

    @Override
    public Ssh1MessageParser<AuthPasswordSSH1> getParser(SshContext context, InputStream stream) {
        return new AuthPasswordParser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<AuthPasswordSSH1> getPreparator(SshContext context) {
        return new AuthPasswordPreparator(context.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<AuthPasswordSSH1> getSerializer(SshContext context) {
        return new AuthPasswordSerializier(this);
    }

    @Override
    public String toShortString() {
        return "AUTH_PASSWORD";
    }
}
