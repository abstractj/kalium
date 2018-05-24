package org.abstractj.kalium.encoders;

import java.util.Base64;

public class Base_64 implements Encoder {

	    public byte[] decode(final String data) {
	        return  Base64.getDecoder().decode(data);
	    }

	    @Override
	    public String encode(byte[] data) {
	    	return Base64.getEncoder().encodeToString(data);
	    }
	
}
