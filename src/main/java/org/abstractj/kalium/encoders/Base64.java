package org.abstractj.kalium.encoders;

/**
 * Converts Base64 Strings. Encoded strings include padding characters.
 * <hr/>
 * The alphabet used for encoding is 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' <br/>
 * The padding character used is '='
 */
public class Base64 implements Encoder {
    private final static char[] B_64_CHARS = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
    private final static char PADDING_CHAR = '=';

    /**
     * Decodes a String of base64 characters into a byte Array.  String with and without padding characters can be decoded.
     * The length of the output array will be 3/4 the length of the input String with padding characters.
     *
     * @param data The base64 String to decode
     * @return A byte array containing the decoded data
     */
    @Override
    public byte[] decode(final String data) {
        return decodeB64(data != null ? data.toCharArray() : new char[0]);
    }

    private static byte[] decodeB64(final char[] data) {

        final int padCharacters = countPadChars(data);


        final int inLength = data.length;
        final byte[] out = new byte[((data.length - padCharacters) * 3) / 4];

        //map 4 encoded chars to 3 output bytes
        for (int i = 0, j = 0; i < inLength; i += 4) {
            int byteGroup = 0;
            for (int k = 0; k < 4 && k + i < inLength; k++) {
                byteGroup |= toDigit(data[i + k], i) << 6 * (3 - k);
            }
            for (int k = 2; k >= 0 && j < out.length; k--) {
                out[j++] = (byte) (byteGroup >>> (k * 8) & 0xff);
            }
        }
        return out;
    }

    /**
     * Counts the number of padding characters in an array of base 64 characters.
     * Padding characters must be at the end of the array.
     *
     * @param data The array of base 64 characters
     * @return the count of padding characters.  This will be 0, 1, or 2 unless the array contains unneccesary padding
     */
    private static int countPadChars(char[] data) {
        int count = 0;
        for (int i = data.length - 1; i >= 0; i--, count++) {
            if (data[i] != PADDING_CHAR) {
                break;
            }
        }
        return count;
    }

    /**
     * Converts a base64 character to an integer. Padding characters are returned as 0
     *
     * @param ch    A character to convert to an integer digit
     * @param index The index of the character in the source
     * @return An integer 0-63
     */
    private static int toDigit(final char ch, final int index) {
        if (ch == PADDING_CHAR) {
            return 0;
        }
        for (int i = 0; i < B_64_CHARS.length; i++) {
            if (ch == B_64_CHARS[i]) {
                return i;
            }
        }
        throw new RuntimeException("Illegal base64 character " + ch + " at index " + index);
    }

    /**
     * Encodes an array of bytes as a string of base64 characters.
     * Padding characters are included in the output.
     * The length of the output String will be 4/3 times the length of the input Array rounded up to the nearest value divisible by 4.
     *
     * @param data The Array of bytes to encode
     * @return The encoded String
     */
    @Override
    public String encode(final byte[] data) {
        if (data == null) {
            return null;
        }
        final int paddingChars = (3 - (data.length % 3)) % 3;

        final int inLength = data.length;
        final char[] out = new char[((inLength + paddingChars) * 4) / 3];

        //map 3 input bytes to 4 output chars
        for (int i = 0, j = 0; i < inLength; i += 3) {
            int byteGroup = 0;
            for (int k = 0; k < 3 && k + i < inLength; k++) {
                byteGroup |= (data[i + k] << 8 * (2 - k));
            }
            for (int k = 3; k >= 0; k--) {
                out[j++] = B_64_CHARS[(byteGroup >>> (k * 6)) & 63];
            }
        }
        //Add padding characters
        for (int k = 1; k <= paddingChars; k++) {
            out[out.length - k] = PADDING_CHAR;
        }
        return new String(out);
    }
}
