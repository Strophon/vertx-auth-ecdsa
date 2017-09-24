package com.foodfeudgame.auth;

public interface EcdsaUserRetriever {
	public EcdsaUserData getUserData(int userId);
	
	public EcdsaUser getAuthorizedUser(EcdsaUserData user);
}
