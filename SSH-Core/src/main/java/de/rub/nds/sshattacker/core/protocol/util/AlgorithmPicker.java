/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/** A utility class to ease the algorithm selection during an SSH transport protocol flow. */
public final class AlgorithmPicker {

    private static final Logger LOGGER = LogManager.getLogger();

    private AlgorithmPicker() {
        super();
    }

    // TODO: Implement pickAlgorithm to satisfy the additional constraints mentioned in RFC 4253
    // Sec. 7.1
    /**
     * Pick the negotiated algorithm based on the supported algorithms sent by client and server.
     * Currently, this method does simply select the first algorithm in the clients' list of
     * supported algorithms which is also supported by the server. However, RFC 4253 Section 7.1
     * defines further constraints regarding the algorithm selection if the algorithm requires an
     * encryption-capable or signature-capable host key.
     *
     * @param clientSupported The list of algorithms supported by the client in order of preference
     * @param serverSupported The list of algorithms supported by the server
     * @param <T> The enumeration type of the algorithm to pick. Will usually be derived from the
     *     provided parameters.
     * @return An Optional containing the negotiated algorithm, if any. Otherwise, the Optional will
     *     be empty.
     */
    public static <T> Optional<T> pickAlgorithm(List<T> clientSupported, List<T> serverSupported) {
        List<T> intersection =
                clientSupported.stream()
                        .filter(serverSupported::contains)
                        .collect(Collectors.toList());
        if (intersection.isEmpty()) {
            LOGGER.warn(
                    "Unable to pick algorithm - no intersection between {} and {}",
                    clientSupported,
                    serverSupported);
            return Optional.empty();
        }
        return Optional.of(intersection.get(0));
    }
}
