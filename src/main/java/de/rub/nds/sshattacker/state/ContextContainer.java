/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.state;

import de.rub.nds.sshattacker.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.exceptions.ContextHandlingException;
import de.rub.nds.sshattacker.transport.Aliasable;
import de.rub.nds.sshattacker.transport.AliasedConnection;
import de.rub.nds.sshattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Manage TLS contexts.
 *
 */
public class ContextContainer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Set<String> knownAliases = new HashSet<>();

    private final Map<String, SshContext> tlsContexts = new HashMap<>();

    /**
     * An inbound TLS context is a context bound to an incoming connection. I.e.
     * it represents a connection that we accepted from a connecting client.
     */
    private final List<SshContext> inboundSshContexts = new ArrayList<>();

    /**
     * An outbound TLS context is a context bound to an outgoing connection.
     * I.e. it represents a connection established by us to a remote server.
     */
    private final List<SshContext> outboundSshContexts = new ArrayList<>();

    /**
     * Get the only defined TLS context.
     * <p>
     * </p>
     * Convenience method, useful when working with a single context only.
     *
     * @return the only known TLS context
     * @throws ConfigurationException if there is more than one TLS context in
     * the container
     *
     */
    public SshContext getSshContext() {
        if (tlsContexts.isEmpty()) {
            throw new ConfigurationException("No context defined.");
        }
        if (tlsContexts.size() > 1) {
            throw new ConfigurationException("getSshContext requires an alias if multiple contexts are defined");
        }
        return tlsContexts.entrySet().iterator().next().getValue();
    }

    /**
     * Get TLS context with the given alias.
     *
     * @param alias
     * @return the context with the given connection end alias
     * @throws ConfigurationException if there is no TLS context with the given
     * alias
     *
     */
    public SshContext getSshContext(String alias) {
        SshContext ctx = tlsContexts.get(alias);
        if (ctx == null) {
            throw new ConfigurationException("No context defined with alias '" + alias + "'.");
        }
        return ctx;
    }

    public void addSshContext(SshContext context) {
        AliasedConnection con = context.getConnection();
        String alias = con.getAlias();
        if (alias == null) {
            throw new ContextHandlingException("Connection end alias not set (null). Can't add the TLS context.");
        }
        if (containsAlias(alias)) {
            throw new ConfigurationException("Connection end alias already in use: " + alias);
        }

        tlsContexts.put(alias, context);
        knownAliases.add(alias);

        if (con.getLocalConnectionEndType() == ConnectionEndType.SERVER) {
            LOGGER.debug("Adding context " + alias + " to inboundSshContexts");
            inboundSshContexts.add(context);
        } else {
            LOGGER.debug("Adding context " + alias + " to outboundSshContexts");
            outboundSshContexts.add(context);
        }
    }

    public List<SshContext> getAllContexts() {
        return new ArrayList<>(tlsContexts.values());
    }

    public List<SshContext> getInboundSshContexts() {
        return inboundSshContexts;
    }

    public List<SshContext> getOutboundSshContexts() {
        return outboundSshContexts;
    }

    public boolean containsAlias(String alias) {
        return knownAliases.contains(alias);
    }

    public boolean containsAllAliases(Collection<? extends String> aliases) {
        return knownAliases.containsAll(aliases);
    }

    public boolean containsAllAliases(Aliasable aliasable) {
        return knownAliases.containsAll(aliasable.getAllAliases());
    }

    public boolean isEmpty() {
        return tlsContexts.isEmpty();
    }

    public void clear() {
        tlsContexts.clear();
        knownAliases.clear();
        inboundSshContexts.clear();
        outboundSshContexts.clear();
    }

    public void removeSshContext(String alias) {
        if (containsAlias(alias)) {
            SshContext removeMe = tlsContexts.get(alias);
            inboundSshContexts.remove(removeMe);
            outboundSshContexts.remove(removeMe);
            tlsContexts.remove(alias);
            knownAliases.remove(alias);
        } else {
            LOGGER.debug("No context with alias " + alias + " found, nothing to remove");
        }
    }

    /**
     * Replace existing SshContext with new SshContext.
     * <p>
     * </p>
     * The SshContext can only be replaced if the connection of both the new and
     * the old SshContext equal.
     *
     * @param newSshContext the new SshContext, not null
     * @throws ConfigurationException if the connections of new and old
     * SshContext differ
     */
    public void replaceSshContext(SshContext newSshContext) {
        String alias = newSshContext.getConnection().getAlias();
        if (!containsAlias(alias)) {
            throw new ConfigurationException("No SshContext to replace for alias " + alias);
        }
        SshContext replaceMe = tlsContexts.get(alias);
        if (!replaceMe.getConnection().equals(newSshContext.getConnection())) {
            throw new ContextHandlingException("Cannot replace SshContext because the new SshContext"
                    + " defines another connection.");
        }
        removeSshContext(alias);
        addSshContext(newSshContext);
    }
}
