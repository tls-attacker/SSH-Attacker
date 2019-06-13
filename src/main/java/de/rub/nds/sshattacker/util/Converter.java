package de.rub.nds.sshattacker.util;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.constants.CharConstants;
import de.rub.nds.sshattacker.constants.DataFormatConstants;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Converter {

    private static final Logger LOGGER = LogManager.getLogger();

    public static ModifiableString listOfAlgorithmsToModifiableString(List list) {
        return ModifiableVariableFactory.safelySetValue(null, listofAlgorithmstoString(list));
    }

    public static String listofAlgorithmstoString(List list) {
        StringBuilder builder = new StringBuilder();
        list.forEach(element -> builder.append(CharConstants.ALGORITHM_SEPARATOR).append(element.toString()));
        builder.deleteCharAt(0); // delete first separator before the first element
        return builder.toString();
    }

    public static List StringToAlgorithms(String string, Class myClass) {

        String[] splitted = string.split(String.valueOf(CharConstants.ALGORITHM_SEPARATOR));
        List list = new LinkedList();
        for (String algo : splitted){
            Enum myenum = Enum.valueOf(myClass, toEnumName(algo).toUpperCase());
            list.add(myenum);
        }
        return list;
    }

    private static String toEnumName(String input) {
        String result = input.replace('-', '_').replace('.', '_').replace('@', '_').replace("3des", "tdes");
        if (result.equals("")) {
            return "none";
        }
        return result;
    }

    public static byte[] byteArraytoMpint(byte[] input) {
        byte[] mpint = input;
        if ((input[0] & 0x80) == 0x80) { // need to append 0 if MSB would be set (twos complement)
            mpint = ArrayConverter.concatenate(new byte[]{0}, input);
        }
        byte[] length = ArrayConverter.intToBytes(mpint.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        mpint = ArrayConverter.concatenate(length, mpint);
        return mpint;
    }

    public static byte[] stringToLengthPrefixedString(String input) {
        try {
            return ArrayConverter.concatenate(ArrayConverter.intToBytes(input.length(), DataFormatConstants.STRING_SIZE_LENGTH), input.getBytes("ISO-8859-1"));
        } catch (UnsupportedEncodingException e) {
            LOGGER.warn("Unsupported Encoding: " + e.getMessage());
            return new byte[0];
        }
    }

    public static String bytesToString(byte[] input) {
        String result = "";
        try {
            result = new String(input, "ISO-8859-1");
        } catch (UnsupportedEncodingException e) {
            LOGGER.warn("Unsupported Encoding: " + e.getMessage());
        }
        return result;
    }

    public static byte[] bytesToLenghPrefixedString(byte[] input) {
        return stringToLengthPrefixedString(bytesToString(input));
    }

    public static byte[] bytesToBytesWithSignByte(byte[] input) {
        if ((input[0] & 0x80) >> 7 == 1) {
            return ArrayConverter.concatenate(new byte[]{0x00}, input);
        }
        return input;
    }
}
