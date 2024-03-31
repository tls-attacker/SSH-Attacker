/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.RequestCompressionMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.RequestCompressionMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.RequestCompressionMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.RequestCompressionMessageSSHV1Serializier;
import java.io.InputStream;

public class RequestCompressionMessageSSH1 extends Ssh1Message<RequestCompressionMessageSSH1> {

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
    public RequestCompressionMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new RequestCompressionMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<RequestCompressionMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new RequestCompressionMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<RequestCompressionMessageSSH1> getPreparator(
            SshContext sshContext) {
        return new RequestCompressionMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<RequestCompressionMessageSSH1> getSerializer(
            SshContext sshContext) {
        return new RequestCompressionMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_REQUEST_COMPRESSION";
    }
}
