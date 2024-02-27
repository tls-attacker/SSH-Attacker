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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ExecCmdMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ExecCmdMessageSSHv1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ExecCmdMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ExecCmdMessageSSHV1Serializier;
import java.io.InputStream;

public class ExecCmdMessageSSH1 extends SshMessage<ExecCmdMessageSSH1> {

    private ModifiableString command;

    public ModifiableString getCommand() {
        return command;
    }

    public void setCommand(ModifiableString disconnectReason) {
        command = disconnectReason;
    }

    public void setCommand(String disconnectReason) {
        command = ModifiableVariableFactory.safelySetValue(command, disconnectReason);
    }

    @Override
    public ExecCmdMessageSSHV1Handler getHandler(SshContext context) {
        return new ExecCmdMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<ExecCmdMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new ExecCmdMessageSSHv1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<ExecCmdMessageSSH1> getPreparator(SshContext context) {
        return new ExecCmdMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<ExecCmdMessageSSH1> getSerializer(SshContext context) {
        return new ExecCmdMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "Disconnect Message";
    }
}
