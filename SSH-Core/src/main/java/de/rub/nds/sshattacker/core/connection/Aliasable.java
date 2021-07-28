/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.connection;

import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import java.util.Collection;
import java.util.Set;

/**
 * Provide common alias methods for SSH context/connection bound objects. SSH contexts are
 * referenced by the alias of their connections. Objects implementing this interface provide a
 * uniform way to access aliases that identify the connections they belong to.
 */
public interface Aliasable {

    void assertAliasesSetProperly() throws ConfigurationException;

    String aliasesToString();

    String getFirstAlias();

    Set<String> getAllAliases();

    boolean containsAlias(String alias);

    boolean containsAllAliases(Collection<String> aliases);
}
