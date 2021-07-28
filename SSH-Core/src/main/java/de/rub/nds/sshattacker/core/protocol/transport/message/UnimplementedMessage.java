/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.UnimplementedMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.UnimplementedMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.handler.UnimplementedMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UnimplementedMessage extends Message<UnimplementedMessage> {

    private ModifiableInteger sequenceNumber;

    public UnimplementedMessage() {
        super(MessageIDConstant.SSH_MSG_UNIMPLEMENTED);
    }

    public ModifiableInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(ModifiableInteger sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.sequenceNumber = ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    @Override
    public UnimplementedMessageHandler getHandler(SshContext context) {
        return new UnimplementedMessageHandler(context);
    }

    @Override
    public UnimplementedMessageSerializer getSerializer() {
        return new UnimplementedMessageSerializer(this);
    }

    @Override
    public UnimplementedMessagePreparator getPreparator(SshContext context) {
        return new UnimplementedMessagePreparator(context, this);
    }
}
