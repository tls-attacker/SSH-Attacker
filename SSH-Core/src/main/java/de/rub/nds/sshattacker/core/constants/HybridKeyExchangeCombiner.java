/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

// Defines the two possibilities to combine key exchanges according to rfc draft
// https://github.com/csosto-pk/pq-ssh/blob/master/draft-kampanakis-ssh-pq-ke.txt
// commit e81667e
public enum HybridKeyExchangeCombiner {
    CLASSICAL_CONCATENATE_POSTQUANTUM,
    POSTQUANTUM_CONCATENATE_CLASSICAL
}
