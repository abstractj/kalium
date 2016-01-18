/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.abstractj.kalium.crypto;

import java.util.Arrays;

public class Util {

    private static final int DEFAULT_SIZE = 32;

    public static byte[] prependZeros(int n, byte[] message) {
        byte[] result = new byte[n + message.length];
        System.arraycopy(message, 0, result, n, message.length);
        return result;
    }

    public static byte[] removeZeros(int n, byte[] message) {
        return Arrays.copyOfRange(message, n, message.length);
    }

    public static void checkLength(byte[] data, int size) {
        if (data == null || data.length != size)
            throw new RuntimeException("Invalid size");
    }

    public static byte[] zeros(int n) {
        return new byte[n];
    }

    public static boolean isValid(int status, String message) {
        if (status != 0)
            throw new RuntimeException(message);
        return true;
    }

    public static byte[] slice(byte[] buffer, int start, int end) {
        return Arrays.copyOfRange(buffer, start, end);
    }

    public static byte[] merge(byte[] signature, byte[] message) {
        byte[] result = new byte[signature.length + message.length];
        System.arraycopy(signature, 0, result, 0, signature.length);
        System.arraycopy(message, 0, result, signature.length, message.length);
        return result;
    }

    public static boolean constantTimeEquals(byte[] b1, byte[] b2) {
        if (b1.length != b2.length) {
            return false;
        }
        int d = 0;
        for (int i = 0; i < b1.length; i++) {
            d |= (b1[i] ^ b2[i]);
        }
        return d == 0;
    }

    public static int constantTimeCompare(byte[] b1, byte[] b2) {
        if (b1.length < b2.length) {
            return -1;
        } else if (b1.length < b2.length) {
            return 1;
        }
        int gt = 0;
        int eq = 1;
        int i = b1.length;
        while (i != 0) {
            i--;
            gt |= ((b2[i] - b1[i]) >> 8) & eq;
            eq &= ((b2[i] ^ b1[i]) - 1) >> 8;
        }
        return (gt + gt + eq) - 1;
    }

    public static boolean constantTimeIsZero(byte[] n) {
        int d = 0;
        for (int i = 0; i < n.length; i++) {
            d |= n[i];
        }
        return d == 0;
    }
}
