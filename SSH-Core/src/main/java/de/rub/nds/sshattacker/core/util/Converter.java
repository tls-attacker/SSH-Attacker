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
import java.util.Iterator;
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
        return ModifiableVariableFactory.safelySetValue(null, listOfNamesToString(list));
    }

    public static String joinStringList(List<String> list, char seperator) {
        if (list.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        Iterator<String> iterator = list.iterator();
        boolean hasNext = iterator.hasNext();
        while (hasNext) {
            builder.append(iterator.next());
            hasNext = iterator.hasNext();
            if (hasNext) {
                builder.append(seperator);
            }
        }

        return builder.toString();
    }

    public static <T extends Enum<T>> String listOfNamesToString(List<T> list) {
        if (list.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();

        Iterator<T> iterator = list.iterator();
        boolean hasNext = iterator.hasNext();
        while (hasNext) {
            builder.append(iterator.next().toString());
            hasNext = iterator.hasNext();
            if (hasNext) {
                builder.append(CharConstants.NAME_LIST_SEPARATOR);
            }
        }

        return builder.toString();
    }

    public static String listOfNameStringsToString(List<String> list) {
        if (list.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();

        Iterator<String> iterator = list.iterator();
        boolean hasNext = iterator.hasNext();
        while (hasNext) {
            builder.append(iterator.next());
            hasNext = iterator.hasNext();
            if (hasNext) {
                builder.append(CharConstants.NAME_LIST_SEPARATOR);
            }
        }

        return builder.toString();
    }

    public static String listOfNamesToString(String[] list) {
        return String.join(CharConstants.NAME_LIST_SEPARATOR, list);
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
        return Arrays.stream(nameListString.split(CharConstants.NAME_LIST_SEPARATOR));
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
        return Arrays.asList(nameListString.split(CharConstants.NAME_LIST_SEPARATOR));
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

    /**
     * Takes a long value and converts it to 8 bytes
     *
     * @param value long value
     * @return long represented by 8 bytes
     */
    public static byte[] longToEightBytes(long value) {
        byte[] result = new byte[8];
        result[0] = (byte) (value >>> 56);
        result[1] = (byte) (value >>> 48);
        result[2] = (byte) (value >>> 40);
        result[3] = (byte) (value >>> 32);
        result[4] = (byte) (value >>> 24);
        result[5] = (byte) (value >>> 16);
        result[6] = (byte) (value >>> 8);
        result[7] = (byte) value;
        return result;
    }

    /**
     * Takes an int value and converts it to 4 bytes
     *
     * @param value int value
     * @return int represented by 4 bytes
     */
    public static byte[] intToFourBytes(int value) {
        byte[] result = new byte[4];
        result[0] = (byte) (value >>> 24);
        result[1] = (byte) (value >>> 16);
        result[2] = (byte) (value >>> 8);
        result[3] = (byte) value;
        return result;
    }

    public static long eigthBytesToLong(byte[] bytes) {
        return (long) (bytes[0] & 0xFF) << 56
                | (long) (bytes[1] & 0xFF) << 48
                | (long) (bytes[2] & 0xFF) << 40
                | (long) (bytes[3] & 0xFF) << 32
                | (long) (bytes[4] & 0xFF) << 24
                | (long) (bytes[5] & 0xFF) << 16
                | (long) (bytes[6] & 0xFF) << 8
                | (long) (bytes[7] & 0xFF);
    }

    public static int fourBytesToInt(byte[] bytes) {
        return (bytes[0] & 0xFF) << 24
                | (bytes[1] & 0xFF) << 16
                | (bytes[2] & 0xFF) << 8
                | bytes[3] & 0xFF;
    }
}
