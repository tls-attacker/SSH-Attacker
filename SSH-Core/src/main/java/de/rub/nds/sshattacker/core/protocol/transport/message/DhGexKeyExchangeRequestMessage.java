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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeRequestMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DhGexKeyExchangeRequestMessage extends SshMessage<DhGexKeyExchangeRequestMessage> {

    private ModifiableInteger minimalGroupSize;
    private ModifiableInteger preferredGroupSize;
    private ModifiableInteger maximalGroupSize;

    public DhGexKeyExchangeRequestMessage() {
        super();
    }

    public DhGexKeyExchangeRequestMessage(DhGexKeyExchangeRequestMessage other) {
        super(other);
        minimalGroupSize =
                other.minimalGroupSize != null ? other.minimalGroupSize.createCopy() : null;
        preferredGroupSize =
                other.preferredGroupSize != null ? other.preferredGroupSize.createCopy() : null;
        maximalGroupSize =
                other.maximalGroupSize != null ? other.maximalGroupSize.createCopy() : null;
    }

    @Override
    public DhGexKeyExchangeRequestMessage createCopy() {
        return new DhGexKeyExchangeRequestMessage(this);
    }

    public ModifiableInteger getMinimalGroupSize() {
        return minimalGroupSize;
    }

    public void setMinimalGroupSize(ModifiableInteger minimalGroupSize) {
        this.minimalGroupSize = minimalGroupSize;
    }

    public void setMinimalGroupSize(int minimalGroupSize) {
        this.minimalGroupSize =
                ModifiableVariableFactory.safelySetValue(this.minimalGroupSize, minimalGroupSize);
    }

    public void setSoftlyMinimalGroupSize(int minimalGroupSize, Config config) {
        if (config.getAlwaysPrepareKex()
                || this.minimalGroupSize == null
                || this.minimalGroupSize.getOriginalValue() == null) {
            this.minimalGroupSize =
                    ModifiableVariableFactory.safelySetValue(
                            this.minimalGroupSize, minimalGroupSize);
        }
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

    public void setSoftlyPreferredGroupSize(int preferredGroupSize, Config config) {
        if (config.getAlwaysPrepareKex()
                || this.preferredGroupSize == null
                || this.preferredGroupSize.getOriginalValue() == null) {
            this.preferredGroupSize =
                    ModifiableVariableFactory.safelySetValue(
                            this.preferredGroupSize, preferredGroupSize);
        }
    }

    public ModifiableInteger getMaximalGroupSize() {
        return maximalGroupSize;
    }

    public void setMaximalGroupSize(ModifiableInteger maximalGroupSize) {
        this.maximalGroupSize = maximalGroupSize;
    }

    public void setMaximalGroupSize(int maximalGroupSize) {
        this.maximalGroupSize =
                ModifiableVariableFactory.safelySetValue(this.maximalGroupSize, maximalGroupSize);
    }

    public void setSoftlyMaximalGroupSize(int maximalGroupSize, Config config) {
        if (config.getAlwaysPrepareKex()
                || this.maximalGroupSize == null
                || this.maximalGroupSize.getOriginalValue() == null) {
            this.maximalGroupSize =
                    ModifiableVariableFactory.safelySetValue(
                            this.maximalGroupSize, maximalGroupSize);
        }
    }

    @Override
    public DhGexKeyExchangeRequestMessageHandler getHandler(SshContext context) {
        return new DhGexKeyExchangeRequestMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        DhGexKeyExchangeRequestMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return DhGexKeyExchangeRequestMessageHandler.SERIALIZER.serialize(this);
    }
}
