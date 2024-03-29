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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.transport.handler.extension.PingExtensionHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.PingExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.PingExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.PingExtensionSerializer;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class PingExtension extends AbstractExtension<PingExtension> {

    private ModifiableInteger versionLength;
    private ModifiableString version;

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
        if (adjustLengthField) {
            setVersionLength(version.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.version = ModifiableVariableFactory.safelySetValue(this.version, version);
    }

    @Override
    public PingExtensionHandler getHandler(SshContext context) {
        return new PingExtensionHandler(context, this);
    }

    @Override
    public PingExtensionParser getParser(SshContext context, InputStream stream) {
        return new PingExtensionParser(stream);
    }

    @Override
    public PingExtensionPreparator getPreparator(SshContext sshContext) {
        return new PingExtensionPreparator(sshContext.getChooser(), this);
    }

    @Override
    public PingExtensionSerializer getSerializer(SshContext context) {
        return new PingExtensionSerializer(this);
    }
}
