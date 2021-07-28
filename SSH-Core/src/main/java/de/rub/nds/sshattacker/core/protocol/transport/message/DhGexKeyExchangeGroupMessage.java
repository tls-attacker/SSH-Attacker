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
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeGroupMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.math.BigInteger;

public class DhGexKeyExchangeGroupMessage extends Message<DhGexKeyExchangeGroupMessage> {

    private ModifiableInteger groupModulusLength;
    private ModifiableBigInteger groupModulus;
    private ModifiableInteger groupGeneratorLength;
    private ModifiableBigInteger groupGenerator;

    public DhGexKeyExchangeGroupMessage() {
        super(MessageIDConstant.SSH_MSG_KEX_DH_GEX_GROUP);
    }

    public ModifiableInteger getGroupModulusLength() {
        return groupModulusLength;
    }

    public void setGroupModulusLength(ModifiableInteger groupModulusLength) {
        this.groupModulusLength = groupModulusLength;
    }

    public void setGroupModulusLength(int groupModulusLength) {
        this.groupModulusLength = ModifiableVariableFactory.safelySetValue(this.groupModulusLength, groupModulusLength);
    }

    public ModifiableBigInteger getGroupModulus() {
        return groupModulus;
    }

    public void setGroupModulus(ModifiableBigInteger groupModulus) {
        setGroupModulus(groupModulus, false);
    }

    public void setGroupModulus(BigInteger groupModulus) {
        setGroupModulus(groupModulus, false);
    }

    public void setGroupModulus(ModifiableBigInteger groupModulus, boolean adjustLengthField) {
        if (adjustLengthField) {
            setGroupModulusLength(groupModulus.getValue().toByteArray().length);
        }
        this.groupModulus = groupModulus;
    }

    public void setGroupModulus(BigInteger groupModulus, boolean adjustLengthField) {
        if (adjustLengthField) {
            setGroupModulusLength(groupModulus.toByteArray().length);
        }
        this.groupModulus = ModifiableVariableFactory.safelySetValue(this.groupModulus, groupModulus);
    }

    public ModifiableInteger getGroupGeneratorLength() {
        return groupGeneratorLength;
    }

    public void setGroupGeneratorLength(ModifiableInteger groupGeneratorLength) {
        this.groupGeneratorLength = groupGeneratorLength;
    }

    public void setGroupGeneratorLength(int groupGeneratorLength) {
        this.groupGeneratorLength = ModifiableVariableFactory.safelySetValue(this.groupGeneratorLength,
                groupGeneratorLength);
    }

    public ModifiableBigInteger getGroupGenerator() {
        return groupGenerator;
    }

    public void setGroupGenerator(ModifiableBigInteger groupGenerator) {
        setGroupGenerator(groupGenerator, false);
    }

    public void setGroupGenerator(BigInteger groupGenerator) {
        setGroupGenerator(groupGenerator, false);
    }

    public void setGroupGenerator(ModifiableBigInteger groupGenerator, boolean adjustLengthField) {
        if (adjustLengthField) {
            setGroupGeneratorLength(groupGenerator.getValue().toByteArray().length);
        }
        this.groupGenerator = groupGenerator;
    }

    public void setGroupGenerator(BigInteger groupGenerator, boolean adjustLengthField) {
        if (adjustLengthField) {
            setGroupGeneratorLength(groupGenerator.toByteArray().length);
        }
        this.groupGenerator = ModifiableVariableFactory.safelySetValue(this.groupGenerator, groupGenerator);
    }

    @Override
    public Handler<DhGexKeyExchangeGroupMessage> getHandler(SshContext context) {
        return new DhGexKeyExchangeGroupMessageHandler(context);
    }

    @Override
    public Serializer<DhGexKeyExchangeGroupMessage> getSerializer() {
        // TODO: Implement serializer for DhGexKeyExchangeGroupMessage
        throw new NotImplementedException("DhGexKeyExchangeGroupMessage::getSerializer()");
    }

    @Override
    public Preparator<DhGexKeyExchangeGroupMessage> getPreparator(SshContext context) {
        // TODO: Implement preparator for DhGexKeyExchangeGroupMessage
        throw new NotImplementedException("DhGexKeyExchangeGroupMessage::getPreparator()");
    }
}
