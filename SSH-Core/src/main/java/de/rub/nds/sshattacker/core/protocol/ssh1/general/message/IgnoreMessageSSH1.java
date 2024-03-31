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
import de.rub.nds.sshattacker.core.protocol.ssh1.general.handler.IgnoreMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.parser.IgnoreMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.preparator.IgnoreMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.serializer.IgnoreMessageSSHV1Serializier;
import java.io.InputStream;

public class IgnoreMessageSSH1 extends Ssh1Message<IgnoreMessageSSH1> {

    private ModifiableString ignoreMessage;

    public ModifiableString getIgnoreMessage() {
        return ignoreMessage;
    }

    public void setIgnoreReason(ModifiableString ignoreMessage) {
        this.ignoreMessage = ignoreMessage;
    }

    public void setIgnoreReason(String ignoreMessage) {
        ModifiableVariableFactory.safelySetValue(this.ignoreMessage, ignoreMessage);
    }

    @Override
    public IgnoreMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new IgnoreMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<IgnoreMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new IgnoreMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<IgnoreMessageSSH1> getPreparator(SshContext sshContext) {
        return new IgnoreMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<IgnoreMessageSSH1> getSerializer(SshContext sshContext) {
        return new IgnoreMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_IGNORE";
    }
}
