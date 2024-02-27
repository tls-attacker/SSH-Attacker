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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.StderrDataMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.StderrDataMessageSSHv1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.StderrDataMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.StderrDataMessageSSHV1Serializier;
import java.io.InputStream;

public class StderrDataMessageSSH1 extends SshMessage<StderrDataMessageSSH1> {

    private ModifiableString data;

    public ModifiableString getData() {
        return data;
    }

    public void setData(ModifiableString disconnectReason) {
        data = disconnectReason;
    }

    public void setData(String disconnectReason) {
        data = ModifiableVariableFactory.safelySetValue(data, disconnectReason);
    }

    @Override
    public StderrDataMessageSSHV1Handler getHandler(SshContext context) {
        return new StderrDataMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<StderrDataMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new StderrDataMessageSSHv1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<StderrDataMessageSSH1> getPreparator(SshContext context) {
        return new StderrDataMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<StderrDataMessageSSH1> getSerializer(SshContext context) {
        return new StderrDataMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "Disconnect Message";
    }
}
