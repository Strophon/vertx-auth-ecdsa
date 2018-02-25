package io.vertx.ext.auth.ecdsa;

public interface EcdsaUserData {

	public byte[] getPubkey();
	
	public String getAuthorities();
}
