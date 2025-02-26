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
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeOldRequestMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DhGexKeyExchangeOldRequestMessage
        extends SshMessage<DhGexKeyExchangeOldRequestMessage> {

    private ModifiableInteger preferredGroupSize;

    public DhGexKeyExchangeOldRequestMessage() {
        super();
    }

    public DhGexKeyExchangeOldRequestMessage(DhGexKeyExchangeOldRequestMessage other) {
        super(other);
        preferredGroupSize =
                other.preferredGroupSize != null ? other.preferredGroupSize.createCopy() : null;
    }

    @Override
    public DhGexKeyExchangeOldRequestMessage createCopy() {
        return new DhGexKeyExchangeOldRequestMessage(this);
    }

    public ModifiableInteger getPreferredGroupSize() {
        return preferredGroupSize;
    }

    public void setPreferredGroupSize(ModifiableInteger preferredGroupSize) {
        this.preferredGroupSize = preferredGroupSize;
    }

    public void setPreferredGroupSize(int preferredGroupSize) {
        this.preferredGroupSize =
                ModifiableVariableFactory.safelySetValue(
                        this.preferredGroupSize, preferredGroupSize);
    }

    public static final DhGexKeyExchangeOldRequestMessageHandler HANDLER =
            new DhGexKeyExchangeOldRequestMessageHandler();

    @Override
    public DhGexKeyExchangeOldRequestMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        DhGexKeyExchangeOldRequestMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return DhGexKeyExchangeOldRequestMessageHandler.SERIALIZER.serialize(this);
    }
}
