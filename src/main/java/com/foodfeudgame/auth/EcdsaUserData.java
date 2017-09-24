package com.foodfeudgame.auth;

public interface EcdsaUserData {
	
	public int getId();
	
	public byte[] getPubkey();
	
	public String getSecretToken();
	
	public String getAuthorities();
}
