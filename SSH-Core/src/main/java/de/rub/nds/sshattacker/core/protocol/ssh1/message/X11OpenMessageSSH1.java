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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.X11OpenMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.X11OpenMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.X11OpenMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.X11OpenMessageSSHV1Serializier;
import java.io.InputStream;

public class X11OpenMessageSSH1 extends SshMessage<X11OpenMessageSSH1> {

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
        this.localChannel =
                ModifiableVariableFactory.safelySetValue(this.localChannel, remoteChannel);
    }

    @Override
    public X11OpenMessageSSHV1Handler getHandler(SshContext context) {
        return new X11OpenMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<X11OpenMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new X11OpenMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<X11OpenMessageSSH1> getPreparator(SshContext context) {
        return new X11OpenMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<X11OpenMessageSSH1> getSerializer(SshContext context) {
        return new X11OpenMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_CHANNEL_OPEN_FAILURE";
    }
}
