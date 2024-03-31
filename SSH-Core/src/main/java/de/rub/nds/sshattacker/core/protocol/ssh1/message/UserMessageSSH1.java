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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.UserMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.UserMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.UserMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.UserMessageSerializier;
import java.io.InputStream;

public class UserMessageSSH1 extends Ssh1Message<UserMessageSSH1> {

    private ModifiableString username;

    public ModifiableString getUsername() {
        return username;
    }

    public void setUsername(ModifiableString username) {
        this.username = username;
    }

    public void setUsername(String username) {
        this.username = ModifiableVariableFactory.safelySetValue(this.username, username);
    }

    @Override
    public UserMessageHandler getHandler(SshContext context) {
        return new UserMessageHandler(context);
    }

    @Override
    public Ssh1MessageParser<UserMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new UserMessageParser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<UserMessageSSH1> getPreparator(SshContext context) {
        return new UserMessagePreparator(context.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<UserMessageSSH1> getSerializer(SshContext context) {
        return new UserMessageSerializier(this);
    }

    @Override
    public String toShortString() {
        return "USER";
    }
}
