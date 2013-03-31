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

package org.abstractj.kalium.encoders;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class Raw {

    private static final Charset charset = Charset.forName("US-ASCII");

    public static byte[] encode(String str) {
        return charset.encode(str).array();
    }

    public static char[] decode(byte[] buffer) {
        ByteBuffer bf = ByteBuffer.allocate(buffer.length);
        bf.put(buffer);
        return charset.decode(bf).array().clone();
    }
}
