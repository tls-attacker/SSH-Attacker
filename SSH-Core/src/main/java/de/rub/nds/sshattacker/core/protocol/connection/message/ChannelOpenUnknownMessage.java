/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenUnknownMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ChannelOpenUnknownMessage extends ChannelOpenMessage<ChannelOpenUnknownMessage> {

    private ModifiableByteArray typeSpecificData;

    public ChannelOpenUnknownMessage() {
        super();
    }

    public ChannelOpenUnknownMessage(ChannelOpenUnknownMessage other) {
        super(other);
        typeSpecificData =
                other.typeSpecificData != null ? other.typeSpecificData.createCopy() : null;
    }

    @Override
    public ChannelOpenUnknownMessage createCopy() {
        return new ChannelOpenUnknownMessage(this);
    }

    public ModifiableByteArray getTypeSpecificData() {
        return typeSpecificData;
    }

    public void setTypeSpecificData(byte[] typeSpecificData) {
        this.typeSpecificData =
                ModifiableVariableFactory.safelySetValue(this.typeSpecificData, typeSpecificData);
    }

    public void setSoftlyTypeSpecificData(byte[] typeSpecificData) {
        if (this.typeSpecificData == null || this.typeSpecificData.getOriginalValue() == null) {
            this.typeSpecificData =
                    ModifiableVariableFactory.safelySetValue(
                            this.typeSpecificData, typeSpecificData);
        }
    }

    public void setTypeSpecificData(ModifiableByteArray typeSpecificData) {
        this.typeSpecificData = typeSpecificData;
    }

    @Override
    public ChannelOpenUnknownMessageHandler getHandler(SshContext context) {
        return new ChannelOpenUnknownMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelOpenUnknownMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
