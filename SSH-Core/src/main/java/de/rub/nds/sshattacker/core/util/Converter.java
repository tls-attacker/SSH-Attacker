/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.util;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class Converter {

    private Converter() {
        super();
    }

    public static <T extends Enum<T>> ModifiableString listOfAlgorithmsToModifiableString(
            List<T> list) {
        return ModifiableVariableFactory.safelySetValue(null, listOfAlgorithmsToString(list));
    }

    public static String joinStringList(List<String> list, char seperator) {
        if (list.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        for (String listElement : list) {
            builder.append(seperator).append(listElement);
        }
        builder.deleteCharAt(0); // delete first separator before the first element
        return builder.toString();
    }

    public static <T extends Enum<T>> String listOfAlgorithmsToString(List<T> list) {
        if (list.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        list.forEach(
                element ->
                        builder.append(CharConstants.ALGORITHM_SEPARATOR)
                                .append(element.toString()));
        builder.deleteCharAt(0); // delete first separator before the first element
        return builder.toString();
    }

    /**
     * Convert a name-list string into a stream of strings.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4251#page-10">name-list specification
     *     in RFC 4251, Section 5 "Data Type Representations Used in the SSH Protocols", page.
     *     10</a>
     * @param nameListString a single string containing a name-list value
     * @return stream of strings
     */
    private static Stream<String> nameListStringToStringStream(String nameListString) {
        return Arrays.stream(
                nameListString.split(String.valueOf(CharConstants.ALGORITHM_SEPARATOR)));
    }

    /**
     * Convert a name-list string into a list of strings.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4251#page-10">name-list specification
     *     in RFC 4251, Section 5 "Data Type Representations Used in the SSH Protocols", page.
     *     10</a>
     * @param nameListString a single string containing a name-list value
     * @return list of strings
     */
    public static List<String> nameListStringToStringList(String nameListString) {
        return nameListStringToStringStream(nameListString).collect(Collectors.toList());
    }

    /**
     * Convert a name-list string into a list of enum values of type {@code enumClass}.
     *
     * <p>Note that the resulting list may have fewer elements than the original name-list if not
     * all names in the name-list have an enum value counterpart.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4251#page-10">name-list specification
     *     in RFC 4251, Section 5 "Data Type Representations Used in the SSH Protocols", page.
     *     10</a>
     * @param <T> the enum type to convert to. The corresponding class is provided as {@code
     *     enumClass}.
     * @param nameListString a single string containing a name-list value
     * @param enumClass the enum class that the elements will be converted to
     * @return list of enums that map to the name sin the name-list
     */
    public static <T extends Enum<T>> List<T> nameListToEnumValues(
            String nameListString, Class<T> enumClass) {
        return nameStreamToEnumValues(nameListStringToStringStream(nameListString), enumClass);
    }

    /**
     * Convert a list of names into a list of enum values of type {@code enumClass}.
     *
     * <p>Note that the resulting list may have fewer elements than the original name-list if not
     * all names in the name-list have an enum value counterpart.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4251#page-10">name-list specification
     *     in RFC 4251, Section 5 "Data Type Representations Used in the SSH Protocols", page.
     *     10</a>
     * @param <T> the enum type to convert to. The corresponding class is provided as {@code
     *     enumClass}.
     * @param nameList a list of strings containing names from a name-list
     * @param enumClass the enum class that the elements will be converted to
     * @return list of enums that map to the names in the name-list
     */
    public static <T extends Enum<T>> List<T> nameListToEnumValues(
            List<String> nameList, Class<T> enumClass) {
        return nameStreamToEnumValues(nameList.stream(), enumClass);
    }

    /**
     * Convert a stream of names into a list of enum values of type {@code enumClass}.
     *
     * <p>Note that the resulting list may have fewer elements than the original name-list if not
     * all names in the name-list have an enum value counterpart.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4251#page-10">name-list specification
     *     in RFC 4251, Section 5 "Data Type Representations Used in the SSH Protocols", page.
     *     10</a>
     * @param <T> the enum type to convert to. The corresponding class is provided as {@code
     *     enumClass}.
     * @param stream a stream of strings containing names from a name-list
     * @param enumClass the enum class that the elements will be converted to
     * @return list of enums that map to the names in the name-list
     */
    private static <T extends Enum<T>> List<T> nameStreamToEnumValues(
            Stream<String> stream, Class<T> enumClass) {
        return stream.map(algorithmName -> nameToEnumValue(algorithmName, enumClass))
                .flatMap(Optional::stream)
                .collect(Collectors.toList());
    }

    /**
     * Convert a single name into an enum values of type {@code enumClass}.
     *
     * @param <T> the enum type to convert to. The corresponding class is provided as {@code
     *     enumClass}.
     * @param name name that matches an enum value's {@code toString()} return value.
     * @param enumClass the enum class that the name will be converted to.
     * @return a value of type {@code enumClass} that corresponds to {@code name}, or no value if no
     *     such item exists.
     */
    public static <T extends Enum<T>> Optional<T> nameToEnumValue(String name, Class<T> enumClass) {
        return Arrays.stream(enumClass.getEnumConstants())
                .filter(enumValue -> name.equals(enumValue.toString()))
                .findFirst();
    }

    public static byte[] bigIntegerToMpint(BigInteger input) {
        byte[] value = input.toByteArray();
        byte[] length =
                ArrayConverter.intToBytes(value.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        return ArrayConverter.concatenate(length, value);
    }

    public static byte[] byteArrayToMpint(byte[] input) {
        byte[] mpint = input;
        if ((input[0] & 0x80) == 0x80) { // need to append 0 if MSB would be set
            // (twos complement)
            mpint = ArrayConverter.concatenate(new byte[] {0}, input);
        }
        byte[] length =
                ArrayConverter.intToBytes(mpint.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        mpint = ArrayConverter.concatenate(length, mpint);
        return mpint;
    }

    public static byte[] stringToLengthPrefixedBinaryString(String input) {
        return bytesToLengthPrefixedBinaryString(input.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] bytesToLengthPrefixedBinaryString(byte[] input) {
        return ArrayConverter.concatenate(
                ArrayConverter.intToBytes(input.length, DataFormatConstants.STRING_SIZE_LENGTH),
                input);
    }

    public static byte booleanToByte(boolean value) {
        return (byte) (value ? 0x01 : 0x00);
    }

    public static boolean byteToBoolean(byte value) {
        return value != (byte) 0x00;
    }

    // TODO: Replace by ArrayConverter.bytesToLong() as soon as fixed
    public static long byteArrayToLong(byte[] value) {
        long result = 0;
        for (int i = 0; i < Long.BYTES && i < value.length; i++) {
            result <<= Byte.SIZE;
            result |= value[i] & 0xFF;
        }
        return result;
    }
}
