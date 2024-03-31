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
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.AuthRsaResponseMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.AuthRsaResponseMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.AuthRsaResponseMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.AuthRsaResponseMessageSSHV1Serializier;
import java.io.InputStream;

public class AuthRsaResponseMessageSSH1 extends Ssh1Message<AuthRsaResponseMessageSSH1> {

    private ModifiableInteger md5Response;

    public ModifiableInteger getMd5Response() {
        return md5Response;
    }

    public void setMd5Response(ModifiableInteger md5Response) {
        this.md5Response = md5Response;
    }

    public void setMd5Response(int md5Response) {
        this.md5Response = ModifiableVariableFactory.safelySetValue(this.md5Response, md5Response);
    }

    @Override
    public AuthRsaResponseMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new AuthRsaResponseMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<AuthRsaResponseMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new AuthRsaResponseMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<AuthRsaResponseMessageSSH1> getPreparator(SshContext sshContext) {
        return new AuthRsaResponseMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<AuthRsaResponseMessageSSH1> getSerializer(SshContext sshContext) {
        return new AuthRsaResponseMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_AUTH_RSA_RESPONSE";
    }
}
