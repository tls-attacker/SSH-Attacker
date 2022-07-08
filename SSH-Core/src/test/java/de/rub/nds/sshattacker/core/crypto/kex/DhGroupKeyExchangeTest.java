/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.sshattacker.core.constants.NamedDhGroup;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class DhGroupKeyExchangeTest {

    /**
     * Provides test data for testing the group selection of DhGroupKeyExchange. Data aims to
     * specify the exact bit length of the implemented groups.
     *
     * @return stream of test vectors, consisting of the preferred group length in bit and the
     *     expected group
     */
    public static Stream<Arguments> initOnPoint() {
        Stream.Builder<Arguments> argumentsBuilder = Stream.builder();
        for (NamedDhGroup group : NamedDhGroup.values()) {
            argumentsBuilder.add(Arguments.of(group.getModulus().bitLength(), group));
        }
        return argumentsBuilder.build();
    }

    /**
     * Provides test data for testing the group selection of DhGroupKeyExchange.
     *
     * @return stream of test vectors, consisting of the preferred group length in bit and the
     *     expected group
     */
    public static Stream<Arguments> randomValues() {
        return Stream.of(
                Arguments.of(1020, NamedDhGroup.GROUP1),
                Arguments.of(1999, NamedDhGroup.GROUP14),
                Arguments.of(2050, NamedDhGroup.GROUP15),
                Arguments.of(4000, NamedDhGroup.GROUP16),
                Arguments.of(5500, NamedDhGroup.GROUP17),
                Arguments.of(7000, NamedDhGroup.GROUP18),
                Arguments.of(9000, NamedDhGroup.GROUP18),
                Arguments.of(Integer.MAX_VALUE, NamedDhGroup.GROUP18),
                Arguments.of((Integer.MIN_VALUE + 10000), NamedDhGroup.GROUP1),
                Arguments.of(50, NamedDhGroup.GROUP1));
    }

    /**
     * Tests the group selection of DhGroupKeyExchange with only the preferred group size as param.
     *
     * @param preferredSize the preferred size for choosing the group
     * @param selectedGroup the expected resulting group
     */
    @ParameterizedTest
    @MethodSource({"initOnPoint", "randomValues"})
    public void testGroupSelectionPref(Integer preferredSize, NamedDhGroup selectedGroup) {
        DhKeyExchange groupKeyExchange = new DhKeyExchange();
        groupKeyExchange.selectGroup(preferredSize);
        assertEquals(selectedGroup.getGenerator(), groupKeyExchange.getGenerator());
        assertEquals(selectedGroup.getModulus(), groupKeyExchange.getModulus());
    }

    /**
     * Provides test data for testing the group selection of DhGroupKeyExchange.
     *
     * @return stream of test vectors, consisting of the minimum, the preferred and the maximum
     *     group length in bit and the expected group
     */
    public static Stream<Arguments> minPrefMaxValues() {
        return Stream.of(
                Arguments.of(1020, 1024, 2000, NamedDhGroup.GROUP1),
                Arguments.of(1999, 2000, 1000, NamedDhGroup.GROUP14),
                Arguments.of(2050, 2050, 2050, NamedDhGroup.GROUP15),
                Arguments.of(4000, 4001, 4002, NamedDhGroup.GROUP16),
                Arguments.of(5500, 5501, 5502, NamedDhGroup.GROUP17),
                Arguments.of(7000, 7001, 7001, NamedDhGroup.GROUP18),
                Arguments.of(5000, 9001, 9002, NamedDhGroup.GROUP18),
                Arguments.of(
                        (Integer.MIN_VALUE + 10000),
                        Integer.MAX_VALUE,
                        Integer.MAX_VALUE,
                        NamedDhGroup.GROUP18),
                Arguments.of((Integer.MIN_VALUE + 10000), 0, 2000, NamedDhGroup.GROUP1),
                Arguments.of(50, 2000, 3000, NamedDhGroup.GROUP14));
    }

    /**
     * Tests the group selection of DhGroupKeyExchange with given min, preferred and max bit length
     * of group.
     *
     * @param minSize minimum size for choosing the group
     * @param preferredSize preferred size for choosing the group
     * @param maxSize maximum size for choosing the group
     * @param selectedGroup the expected resulting group
     */
    @ParameterizedTest
    @MethodSource("minPrefMaxValues")
    public void testGroupSelection(
            Integer minSize, Integer preferredSize, Integer maxSize, NamedDhGroup selectedGroup) {
        DhKeyExchange groupKeyExchange = new DhKeyExchange();
        groupKeyExchange.selectGroup(minSize, preferredSize, maxSize);
        assertEquals(selectedGroup.getGenerator(), groupKeyExchange.getGenerator());
        assertEquals(selectedGroup.getModulus(), groupKeyExchange.getModulus());
    }
}
