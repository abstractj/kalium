/*
 * Copyright 2013 Bruno Oliveira, and individual contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.abstractj.kalium.crypto;

import java.util.Arrays;

public class Util {

    public static final int DEFAULT_SIZE = 32;

    public static byte[] merge(byte[] signature, byte[] message){
        byte[] result = new byte[signature.length + message.length];
        System.arraycopy(signature, 0, result, 0, signature.length);
        System.arraycopy(message, 0, result, signature.length - 1, message.length);
        return result;
    }
    public static byte[] prependZeros(int n, byte[] message) {
        byte[] result = new byte[n + message.length];
        Arrays.fill(result, (byte) 0);
        System.arraycopy(message, 0, result, n, message.length);
        return result;
    }

    public static byte[] removeZeros(int n, byte[] message) {
        byte[] buffer = Arrays.copyOfRange(message, n, message.length);
        return buffer;
    }

    public static byte[] prependZeros(String message) {
        return prependZeros(DEFAULT_SIZE, message.getBytes());
    }

    public static byte[] removeZeros(byte[] message) {
        return removeZeros(DEFAULT_SIZE, message);
    }

    public static void checkLength(byte[] data, int size) {
        if (data == null || data.length != size)
            throw new RuntimeException("Invalid size");
    }

    public static byte[] zeros(int n) {
        return new byte[n];
    }

    public static void isValid(int status) {
        if (status != 0)
            throw new RuntimeException("Invalid key");
    }

    public static boolean isValid(int status, String message) {
        if (status != 0)
            throw new RuntimeException(message);
        return true;
    }

    public static byte[] slice(byte[] buffer, int start, int end) {
        return Arrays.copyOfRange(buffer, start, end);
    }

}
