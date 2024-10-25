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
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.UserMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.UserMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.UserMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.UserMessageSerializier;
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
    public UserMessageHandler getHandler(SshContext sshContext) {
        return new UserMessageHandler(sshContext);
    }

    @Override
    public Ssh1MessageParser<UserMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new UserMessageParser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<UserMessageSSH1> getPreparator(SshContext sshContext) {
        return new UserMessagePreparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<UserMessageSSH1> getSerializer(SshContext sshContext) {
        return new UserMessageSerializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_USER";
    }
}
