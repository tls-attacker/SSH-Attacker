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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.AuthRsaResponseMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.AuthRsaResponseMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.AuthRsaResponseMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.AuthRsaResponseMessageSSHV1Serializier;
import java.io.InputStream;

public class AuthRsaResponseMessageSSH1 extends SshMessage<AuthRsaResponseMessageSSH1> {

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
    public AuthRsaResponseMessageSSHV1Handler getHandler(SshContext context) {
        return new AuthRsaResponseMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<AuthRsaResponseMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new AuthRsaResponseMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<AuthRsaResponseMessageSSH1> getPreparator(SshContext context) {
        return new AuthRsaResponseMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<AuthRsaResponseMessageSSH1> getSerializer(SshContext context) {
        return new AuthRsaResponseMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_EOF";
    }
}
