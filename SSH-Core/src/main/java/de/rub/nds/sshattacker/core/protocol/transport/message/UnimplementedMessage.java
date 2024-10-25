/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.UnimplementedMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.UnimplementedMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.UnimplementedMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.UnimplementedMessageSerializer;
import java.io.InputStream;

public class UnimplementedMessage extends SshMessage<UnimplementedMessage> {

    private ModifiableInteger sequenceNumber;

    public ModifiableInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(ModifiableInteger sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.sequenceNumber =
                ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    @Override
    public UnimplementedMessageHandler getHandler(SshContext context) {
        return new UnimplementedMessageHandler(context);
    }

    @Override
    public UnimplementedMessageParser getParser(SshContext context, InputStream stream) {
        return new UnimplementedMessageParser(stream);
    }

    @Override
    public UnimplementedMessagePreparator getPreparator(SshContext context) {
        return new UnimplementedMessagePreparator(context.getChooser(), this);
    }

    @Override
    public UnimplementedMessageSerializer getSerializer(SshContext context) {
        return new UnimplementedMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "UNIMPLEMENTED";
    }
}
