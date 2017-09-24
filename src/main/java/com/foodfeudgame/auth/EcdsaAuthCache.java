package com.foodfeudgame.auth;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

public interface EcdsaAuthCache {
	public void getChallenge(int userId, Handler<AsyncResult<String>> handler);
}
