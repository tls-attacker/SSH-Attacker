/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.server.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.handler.X11OpenMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.parser.X11OpenMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.preparator.X11OpenMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.serializer.X11OpenMessageSSHV1Serializier;
import java.io.InputStream;

public class X11OpenMessageSSH1 extends Ssh1Message<X11OpenMessageSSH1> {

    private ModifiableInteger localChannel;
    private ModifiableString originatorString;

    public ModifiableString getOriginatorString() {
        return originatorString;
    }

    public void setOriginatorString(ModifiableString originatorString) {
        this.originatorString = originatorString;
    }

    public void setOriginatorString(String originatorString) {
        this.originatorString =
                ModifiableVariableFactory.safelySetValue(this.originatorString, originatorString);
    }

    public ModifiableInteger getLocalChannel() {
        return localChannel;
    }

    public void setLocalChannel(ModifiableInteger localChannel) {
        this.localChannel = localChannel;
    }

    public void setLocalChannel(int remoteChannel) {
        localChannel = ModifiableVariableFactory.safelySetValue(localChannel, remoteChannel);
    }

    @Override
    public X11OpenMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new X11OpenMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<X11OpenMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new X11OpenMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<X11OpenMessageSSH1> getPreparator(SshContext sshContext) {
        return new X11OpenMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<X11OpenMessageSSH1> getSerializer(SshContext sshContext) {
        return new X11OpenMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_SMSG_X11_OPEN";
    }
}
