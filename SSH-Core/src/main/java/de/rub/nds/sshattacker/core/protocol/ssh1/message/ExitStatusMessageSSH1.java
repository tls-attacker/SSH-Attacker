/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ExitConfirmationMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ExitStatusMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ExitConfirmationMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ExitStatusMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ExitConfirmationMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ExitStatusMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ExitConfirmationMessageSSHV1Serializier;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ExitStatusMessageSSHV1Serializier;

import java.io.InputStream;

public class ExitStatusMessageSSH1 extends SshMessage<ExitStatusMessageSSH1> {

    private ModifiableInteger exitStatus;

    public ModifiableInteger getExitStatus() {
        return exitStatus;
    }

    public void setExitStatus(ModifiableInteger exitStatus) {
        this.exitStatus = exitStatus;
    }

    public void setExitStatus(int exitStatus) {
        this.exitStatus =
                ModifiableVariableFactory.safelySetValue(this.exitStatus, exitStatus);
    }

    @Override
    public ExitStatusMessageSSHV1Handler getHandler(SshContext context) {
        return new ExitStatusMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<ExitStatusMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new ExitStatusMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<ExitStatusMessageSSH1> getPreparator(SshContext context) {
        return new ExitStatusMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<ExitStatusMessageSSH1> getSerializer(SshContext context) {
        return new ExitStatusMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_EOF";
    }
}
