/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeGroupMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.math.BigInteger;

public class DhGexKeyExchangeGroupMessage extends SshMessage<DhGexKeyExchangeGroupMessage> {

    private ModifiableInteger groupModulusLength;
    private ModifiableBigInteger groupModulus;
    private ModifiableInteger groupGeneratorLength;
    private ModifiableBigInteger groupGenerator;

    public ModifiableInteger getGroupModulusLength() {
        return groupModulusLength;
    }

    public void setGroupModulusLength(ModifiableInteger groupModulusLength) {
        this.groupModulusLength = groupModulusLength;
    }

    public void setGroupModulusLength(int groupModulusLength) {
        this.groupModulusLength =
                ModifiableVariableFactory.safelySetValue(
                        this.groupModulusLength, groupModulusLength);
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
        this.groupModulus = groupModulus;
        if (adjustLengthField) {
            setGroupModulusLength(this.groupModulus.getValue().toByteArray().length);
        }
    }

    public void setGroupModulus(BigInteger groupModulus, boolean adjustLengthField) {
        this.groupModulus =
                ModifiableVariableFactory.safelySetValue(this.groupModulus, groupModulus);
        if (adjustLengthField) {
            setGroupModulusLength(this.groupModulus.getValue().toByteArray().length);
        }
    }

    public ModifiableInteger getGroupGeneratorLength() {
        return groupGeneratorLength;
    }

    public void setGroupGeneratorLength(ModifiableInteger groupGeneratorLength) {
        this.groupGeneratorLength = groupGeneratorLength;
    }

    public void setGroupGeneratorLength(int groupGeneratorLength) {
        this.groupGeneratorLength =
                ModifiableVariableFactory.safelySetValue(
                        this.groupGeneratorLength, groupGeneratorLength);
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
        this.groupGenerator = groupGenerator;
        if (adjustLengthField) {
            setGroupGeneratorLength(this.groupGenerator.getValue().toByteArray().length);
        }
    }

    public void setGroupGenerator(BigInteger groupGenerator, boolean adjustLengthField) {
        this.groupGenerator =
                ModifiableVariableFactory.safelySetValue(this.groupGenerator, groupGenerator);
        if (adjustLengthField) {
            setGroupGeneratorLength(this.groupGenerator.getValue().toByteArray().length);
        }
    }

    @Override
    public DhGexKeyExchangeGroupMessageHandler getHandler(SshContext context) {
        return new DhGexKeyExchangeGroupMessageHandler(context, this);
    }
}
