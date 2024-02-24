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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.StdinDataMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.StdoutDataMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.StdinDataMessageSSHv1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.StdoutDataMessageSSHv1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.StdinDataMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.StdoutDataMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.StdinDataMessageSSHV1Serializier;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.StdoutDataMessageSSHV1Serializier;

import java.io.InputStream;

public class StdoutDataMessageSSH1 extends SshMessage<StdoutDataMessageSSH1> {

    private ModifiableString data;

    public ModifiableString getData() {
        return data;
    }

    public void setData(ModifiableString disconnectReason) {
        data = disconnectReason;
    }

    public void setData(String disconnectReason) {
        data =
                ModifiableVariableFactory.safelySetValue(data, disconnectReason);
    }

    @Override
    public StdoutDataMessageSSHV1Handler getHandler(SshContext context) {
        return new StdoutDataMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<StdoutDataMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new StdoutDataMessageSSHv1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<StdoutDataMessageSSH1> getPreparator(SshContext context) {
        return new StdoutDataMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<StdoutDataMessageSSH1> getSerializer(SshContext context) {
        return new StdoutDataMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "Disconnect Message";
    }
}
