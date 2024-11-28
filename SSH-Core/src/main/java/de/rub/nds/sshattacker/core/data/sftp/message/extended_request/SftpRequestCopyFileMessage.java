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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestCopyFileMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;

public class SftpRequestCopyFileMessage
        extends SftpRequestExtendedWithPathMessage<SftpRequestCopyFileMessage> {

    // path is the source path

    private ModifiableInteger destinationPathLength;
    private ModifiableString destinationPath;
    private ModifiableByte overwriteDestination;

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

    public void setSoftlyOverwriteDestination(byte overwriteDestination) {
        if (this.overwriteDestination == null
                || this.overwriteDestination.getOriginalValue() == null) {
            this.overwriteDestination =
                    ModifiableVariableFactory.safelySetValue(
                            this.overwriteDestination, overwriteDestination);
        }
    }

    public void setOverwriteDestination(boolean overwriteDestination) {
        setOverwriteDestination(Converter.booleanToByte(overwriteDestination));
    }

    public void setSoftlyOverwriteDestination(boolean overwriteDestination) {
        setSoftlyOverwriteDestination(Converter.booleanToByte(overwriteDestination));
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

    public ModifiableString getDestinationPath() {
        return destinationPath;
    }

    public void setDestinationPath(ModifiableString destinationPath) {
        setDestinationPath(destinationPath, false);
    }

    public void setDestinationPath(String destinationPath) {
        setDestinationPath(destinationPath, false);
    }

    public void setDestinationPath(ModifiableString destinationPath, boolean adjustLengthField) {
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

    public void setSoftlyDestinationPath(
            String destinationPath, boolean adjustLengthField, Config config) {
        if (this.destinationPath == null || this.destinationPath.getOriginalValue() == null) {
            this.destinationPath =
                    ModifiableVariableFactory.safelySetValue(this.destinationPath, destinationPath);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || destinationPathLength == null
                    || destinationPathLength.getOriginalValue() == null) {
                setDestinationPathLength(
                        this.destinationPath.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    @Override
    public SftpRequestCopyFileMessageHandler getHandler(SshContext context) {
        return new SftpRequestCopyFileMessageHandler(context, this);
    }
}
