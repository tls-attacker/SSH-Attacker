/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.transport.handler.extension.PingExtensionHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class PingExtension extends AbstractExtension<PingExtension> {

    private ModifiableInteger versionLength;
    private ModifiableString version;

    public PingExtension() {
        super();
    }

    public PingExtension(PingExtension other) {
        super(other);
        versionLength = other.versionLength != null ? other.versionLength.createCopy() : null;
        version = other.version != null ? other.version.createCopy() : null;
    }

    @Override
    public PingExtension createCopy() {
        return new PingExtension(this);
    }

    public ModifiableInteger getVersionLength() {
        return versionLength;
    }

    public void setVersionLength(ModifiableInteger versionLength) {
        this.versionLength = versionLength;
    }

    public void setVersionLength(int versionLength) {
        this.versionLength =
                ModifiableVariableFactory.safelySetValue(this.versionLength, versionLength);
    }

    public ModifiableString getVersion() {
        return version;
    }

    public void setVersion(ModifiableString version) {
        setVersion(version, false);
    }

    public void setVersion(ModifiableString version, boolean adjustLengthField) {
        if (adjustLengthField) {
            setVersionLength(version.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.version = version;
    }

    public void setVersion(String version) {
        setVersion(version, false);
    }

    public void setVersion(String version, boolean adjustLengthField) {
        this.version = ModifiableVariableFactory.safelySetValue(this.version, version);
        if (adjustLengthField) {
            setVersionLength(this.version.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setSoftlyVersion(String version, boolean adjustLengthField, Config config) {
        if (this.version == null || this.version.getOriginalValue() == null) {
            this.version = ModifiableVariableFactory.safelySetValue(this.version, version);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || versionLength == null
                    || versionLength.getOriginalValue() == null) {
                setVersionLength(
                        this.version.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
        }
    }

    @Override
    public PingExtensionHandler getHandler(SshContext context) {
        return new PingExtensionHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        PingExtensionHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return PingExtensionHandler.SERIALIZER.serialize(this);
    }
}
