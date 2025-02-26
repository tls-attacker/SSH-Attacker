/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.path.ModifiablePath;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestCopyFileMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class SftpRequestCopyFileMessage
        extends SftpRequestExtendedWithPathMessage<SftpRequestCopyFileMessage> {

    // path is the source path

    private ModifiableInteger destinationPathLength;
    private ModifiablePath destinationPath;
    private ModifiableByte overwriteDestination;

    public SftpRequestCopyFileMessage() {
        super();
    }

    public SftpRequestCopyFileMessage(SftpRequestCopyFileMessage other) {
        super(other);
        destinationPathLength =
                other.destinationPathLength != null
                        ? other.destinationPathLength.createCopy()
                        : null;
        destinationPath = other.destinationPath != null ? other.destinationPath.createCopy() : null;
        overwriteDestination =
                other.overwriteDestination != null ? other.overwriteDestination.createCopy() : null;
    }

    @Override
    public SftpRequestCopyFileMessage createCopy() {
        return new SftpRequestCopyFileMessage(this);
    }

    public ModifiableByte getOverwriteDestination() {
        return overwriteDestination;
    }

    public void setOverwriteDestination(ModifiableByte overwriteDestination) {
        this.overwriteDestination = overwriteDestination;
    }

    public void setOverwriteDestination(byte overwriteDestination) {
        this.overwriteDestination =
                ModifiableVariableFactory.safelySetValue(
                        this.overwriteDestination, overwriteDestination);
    }

    public void setOverwriteDestination(boolean overwriteDestination) {
        setOverwriteDestination(Converter.booleanToByte(overwriteDestination));
    }

    public ModifiableInteger getDestinationPathLength() {
        return destinationPathLength;
    }

    public void setDestinationPathLength(ModifiableInteger destinationPathLength) {
        this.destinationPathLength = destinationPathLength;
    }

    public void setDestinationPathLength(int destinationPathLength) {
        this.destinationPathLength =
                ModifiableVariableFactory.safelySetValue(
                        this.destinationPathLength, destinationPathLength);
    }

    public ModifiablePath getDestinationPath() {
        return destinationPath;
    }

    public void setDestinationPath(ModifiablePath destinationPath) {
        setDestinationPath(destinationPath, false);
    }

    public void setDestinationPath(String destinationPath) {
        setDestinationPath(destinationPath, false);
    }

    public void setDestinationPath(ModifiablePath destinationPath, boolean adjustLengthField) {
        if (adjustLengthField) {
            setDestinationPathLength(
                    destinationPath.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.destinationPath = destinationPath;
    }

    public void setDestinationPath(String destinationPath, boolean adjustLengthField) {
        this.destinationPath =
                ModifiableVariableFactory.safelySetValue(this.destinationPath, destinationPath);
        if (adjustLengthField) {
            setDestinationPathLength(
                    this.destinationPath.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public static final SftpRequestCopyFileMessageHandler HANDLER =
            new SftpRequestCopyFileMessageHandler();

    @Override
    public SftpRequestCopyFileMessageHandler getHandler() {
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
        SftpRequestCopyFileMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpRequestCopyFileMessageHandler.SERIALIZER.serialize(this);
    }
}
