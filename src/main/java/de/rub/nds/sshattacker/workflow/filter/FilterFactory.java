package de.rub.nds.sshattacker.workflow.filter;

import de.rub.nds.sshattacker.config.Config;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FilterFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static Filter createWorkflowTraceFilter(FilterType type, Config config) {
        switch (type) {
            case DEFAULT:
                return new DefaultFilter(config);
//            case DISCARD_RECORDS:
//                return new DiscardRecordsFilter(config);
            default:
                throw new UnsupportedOperationException(type.name() + " not yet implemented");
        }
    }

    private FilterFactory() {
    }
}
