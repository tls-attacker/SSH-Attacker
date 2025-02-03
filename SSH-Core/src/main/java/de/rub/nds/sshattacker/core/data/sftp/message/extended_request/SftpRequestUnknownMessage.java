/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestUnknownMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestUnknownMessage
        extends SftpRequestExtendedMessage<SftpRequestUnknownMessage> {

    private ModifiableByteArray requestSpecificData;

    public SftpRequestUnknownMessage() {
        super();
    }

    public SftpRequestUnknownMessage(SftpRequestUnknownMessage other) {
        super(other);
        requestSpecificData =
                other.requestSpecificData != null ? other.requestSpecificData.createCopy() : null;
    }

    @Override
    public SftpRequestUnknownMessage createCopy() {
        return new SftpRequestUnknownMessage(this);
    }

    public ModifiableByteArray getRequestSpecificData() {
        return requestSpecificData;
    }

    public void setRequestSpecificData(ModifiableByteArray requestSpecificData) {
        this.requestSpecificData = requestSpecificData;
    }

    public void setRequestSpecificData(byte[] requestSpecificData) {
        this.requestSpecificData =
                ModifiableVariableFactory.safelySetValue(
                        this.requestSpecificData, requestSpecificData);
    }

    public void setSoftlyRequestSpecificData(byte[] requestSpecificData) {
        this.requestSpecificData =
                ModifiableVariableFactory.softlySetValue(
                        this.requestSpecificData, requestSpecificData);
    }

    public static final SftpRequestUnknownMessageHandler HANDLER =
            new SftpRequestUnknownMessageHandler();

    @Override
    public SftpRequestUnknownMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpRequestUnknownMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestUnknownMessageHandler.SERIALIZER.serialize(this);
    }
}
