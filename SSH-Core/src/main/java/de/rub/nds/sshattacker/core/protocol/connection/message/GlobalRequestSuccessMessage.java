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
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestSuccessMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestSuccessMessage extends SshMessage<GlobalRequestSuccessMessage> {

    private ModifiableByteArray responseSpecificData;

    public GlobalRequestSuccessMessage() {
        super();
    }

    public GlobalRequestSuccessMessage(GlobalRequestSuccessMessage other) {
        super(other);
        responseSpecificData =
                other.responseSpecificData != null ? other.responseSpecificData.createCopy() : null;
    }

    @Override
    public GlobalRequestSuccessMessage createCopy() {
        return new GlobalRequestSuccessMessage(this);
    }

    public ModifiableByteArray getResponseSpecificData() {
        return responseSpecificData;
    }

    public void setResponseSpecificData(ModifiableByteArray responseSpecificData) {
        this.responseSpecificData = responseSpecificData;
    }

    public void setResponseSpecificData(byte[] responseSpecificData) {
        this.responseSpecificData =
                ModifiableVariableFactory.safelySetValue(
                        this.responseSpecificData, responseSpecificData);
    }

    @Override
    public GlobalRequestSuccessMessageHandler getHandler(SshContext context) {
        return new GlobalRequestSuccessMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        GlobalRequestSuccessMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
