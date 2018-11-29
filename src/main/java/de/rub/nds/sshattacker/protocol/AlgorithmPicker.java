package de.rub.nds.sshattacker.protocol;

import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlgorithmPicker {

    private static final Logger LOGGER = LogManager.getLogger();

    // TODO key exchange algorithm has a special pattern
    private static <T> T pickAlgorithm(List<T> left, List<T> right){
        List<T> intersection = left.stream().filter(right::contains).collect(Collectors.toList());
        if (intersection.isEmpty()){
            LOGGER.debug("No intersection between " + left + "and " + right);
        }
        return intersection.get(0);
    }
}
