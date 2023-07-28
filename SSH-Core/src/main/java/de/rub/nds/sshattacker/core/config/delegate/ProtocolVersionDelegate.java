/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.ProtocolVersion;
import de.rub.nds.sshattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

public class ProtocolVersionDelegate extends Delegate {

    @Parameter(names = "-version", description = "Highest supported protocol version ")
    private ProtocolVersion protocolVersion = null;

    public ProtocolVersionDelegate() {}

    public ProtocolVersionDelegate(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    @Override
    public void applyDelegate(Config config) {
        if (protocolVersion == null) {
            return;
        }

        config.setProtocolVersion(protocolVersion);
        TransportHandlerType th = TransportHandlerType.TCP;
        if (config.getProtocolVersion().isSSHv2()) {
            config.setDefaultLayerConfiguration(LayerConfiguration.SSHv2);
        } else if (config.getProtocolVersion().isSSHv1()) {
            config.setDefaultLayerConfiguration(LayerConfiguration.SSHv1);
        } else {
            LOGGER.error("[bro] does not initalize with sshv1 or sshv2");
            throw new RuntimeException();
        }

        /*        if (config.getDefaultClientConnection() == null) {
                    config.setDefaultClientConnection(new OutboundConnection());
                }
                if (config.getDefaultServerConnection() == null) {
                    config.setDefaultServerConnection(new InboundConnection());
                }
                config.getDefaultClientConnection().setTransportHandlerType(th);
                config.getDefaultServerConnection().setTransportHandlerType(th);
        */
    }
}
