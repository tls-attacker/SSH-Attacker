/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.context;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.layer.LayerStack;
import de.rub.nds.sshattacker.core.state.Context;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;

/** A LayerContext holds all runtime variables of a layer during a connection. */
public abstract class LayerContext {

    private Context context;

    protected LayerContext(Context context) {
        this.context = context;
    }

    public Context getContext() {
        return context;
    }

    public void setContext(Context context) {
        this.context = context;
    }

    /*
     * Helper functions that return variables of the containing context
     */

    public Config getConfig() {
        return context.getConfig();
    }

    public Chooser getChooser() {
        return context.getChooser();
    }

    public LayerStack getLayerStack() {
        return context.getLayerStack();
    }

    public ConnectionEndType getTalkingConnectionEndType() {
        return context.getTalkingConnectionEndType();
    }

    public void setTalkingConnectionEndType(ConnectionEndType endType) {
        context.setTalkingConnectionEndType(endType);
    }

    public AliasedConnection getConnection() {
        return getContext().getConnection();
    }

    public void setConnection(AliasedConnection connection) {
        getContext().setConnection(connection);
    }

    public TransportHandler getTransportHandler() {
        return context.getTransportHandler();
    }

    public void setTransportHandler(TransportHandler transportHandler) {
        context.setTransportHandler(transportHandler);
    }
}
