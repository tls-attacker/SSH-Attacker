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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.RequestCompressionMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.RequestCompressionMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.RequestCompressionMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.RequestCompressionMessageSSHV1Serializier;
import java.io.InputStream;

public class RequestCompressionMessageSSH1 extends SshMessage<RequestCompressionMessageSSH1> {

    private ModifiableInteger compressionState;

    public ModifiableInteger getCompressionState() {
        return compressionState;
    }

    public void setCompressionState(ModifiableInteger compressionState) {
        this.compressionState = compressionState;
    }

    public void setCompressionState(int compressionState) {
        this.compressionState =
                ModifiableVariableFactory.safelySetValue(this.compressionState, compressionState);
    }

    @Override
    public RequestCompressionMessageSSHV1Handler getHandler(SshContext context) {
        return new RequestCompressionMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<RequestCompressionMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new RequestCompressionMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<RequestCompressionMessageSSH1> getPreparator(SshContext context) {
        return new RequestCompressionMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<RequestCompressionMessageSSH1> getSerializer(SshContext context) {
        return new RequestCompressionMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_EOF";
    }
}
