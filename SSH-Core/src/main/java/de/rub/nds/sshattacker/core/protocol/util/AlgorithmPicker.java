/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.util;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlgorithmPicker {

    private static final Logger LOGGER = LogManager.getLogger();

    public static <T> Optional<T> pickAlgorithm(List<T> left, List<T> right) {
        List<T> intersection = left.stream().filter(right::contains).collect(Collectors.toList());
        if (intersection.isEmpty()) {
            LOGGER.debug("No intersection between " + left + "and " + right);
            return Optional.empty();
        }
        return Optional.of(intersection.get(0));
    }
}
