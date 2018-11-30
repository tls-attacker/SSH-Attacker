package de.rub.nds.sshattacker.util;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.constants.CharConstants;
import de.rub.nds.sshattacker.constants.DataFormatConstants;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Converter {

    private static final Logger LOGGER = LogManager.getLogger();

    
    public static ModifiableString listOfAlgorithmsToModifiableString(List list){
        return ModifiableVariableFactory.safelySetValue(null, listofAlgorithmstoString(list));
    }
    
    public static String listofAlgorithmstoString(List list){
        StringBuilder builder = new StringBuilder();
        list.forEach(element -> builder.append(CharConstants.ALGORITHM_SEPARATOR).append(element));
        builder.deleteCharAt(0); // delete first separator before the first element
        return builder.toString();
    }
    
    public static List StringToAlgorithms(String string, Class myClass){
        String[] splitted = string.split(String.valueOf(CharConstants.ALGORITHM_SEPARATOR));
        // TODO make robust
        return Arrays.stream(splitted).map(s -> Enum.valueOf(myClass, string)).collect(Collectors.toList());
    }
    
    public static byte[] byteArraytoMpint(byte[] input){
        byte[] mpint = input;
        if ((input[0] & 0x80) == 0x80){ // need to append 0 if MSB would be set (twos complement)
            mpint = concatenate(new byte[] {0}, input);
        }
        byte[] length = ArrayConverter.intToBytes(mpint.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        mpint = concatenate(length, mpint);
        return mpint;
    }
    
    public static byte[] stringToLengthPrefixedString(String input){
        return concatenate(ArrayConverter.intToBytes(input.length(), DataFormatConstants.STRING_SIZE_LENGTH),input.getBytes());
    }
    
    /**
     * Concatenates an array of byte[] to one big byte[]
     *
     * @param arrays the array of byte[] to concatenate
     * @return an array of byte[] as one big byte[]
     */
    public static byte[] concatenate(byte[]... arrays) {
        if (arrays == null || arrays.length == 0) {
            throw new IllegalArgumentException("The minimal number of parameters for this function is one");
        }
        int length = 0;
        for (final byte[] a : arrays) {
            if (a != null) {
                length += a.length;
            }
        }
        byte[] result = new byte[length];
        int currentOffset = 0;
        for (final byte[] a : arrays) {
            if (a != null) {
                System.arraycopy(a, 0, result, currentOffset, a.length);
                currentOffset += a.length;
            }
        }
        return result;
    }
}