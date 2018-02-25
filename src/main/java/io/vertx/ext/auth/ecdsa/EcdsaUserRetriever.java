package io.vertx.ext.auth.ecdsa;

public interface EcdsaUserRetriever {
	public EcdsaUserData getUserData(int userId);
	
	public EcdsaUser getAuthorizedUser(EcdsaUserData user, String challenge);
}
