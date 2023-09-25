/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.connection.InboundConnection;
import de.rub.nds.sshattacker.core.constants.RunningModeType;

public class ServerDelegate extends Delegate {

    @Parameter(names = "-port", required = true, description = "ServerPort")
    protected Integer port = null;

    @Parameter(names = "-endless", description = "EndlessMode")
    protected Boolean endless = null;

    public ServerDelegate() {}

    public Integer getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public Boolean getEndless() {
        return endless;
    }

    public void setEndless(Boolean endless) {
        this.endless = endless;
    }

    @Override
    public void applyDelegate(Config config) {

        config.setDefaultRunningMode(RunningModeType.SERVER);

        int parsedPort = parsePort(port);
        InboundConnection inboundConnection = config.getDefaultServerConnection();
        if (inboundConnection != null) {
            inboundConnection.setPort(parsedPort);
        } else {
            inboundConnection = new InboundConnection(parsedPort);
            config.setDefaultServerConnection(inboundConnection);
        }

        if (endless) {
            LOGGER.debug("ENDLESS");
            config.setWorkflowExecutorShouldClose(false);
            config.setStopActionsAfterDisconnect(false);
        }
    }

    private int parsePort(Integer port) {
        if (port == null) {
            throw new ParameterException("Port must be set, but was not specified");
        }
        if (port < 0 || port > 65535) {
            throw new ParameterException("Port must be in interval [0,65535], but is " + port);
        }
        return port;
    }
}
