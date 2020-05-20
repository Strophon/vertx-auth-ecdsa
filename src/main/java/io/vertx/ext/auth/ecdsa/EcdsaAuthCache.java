package io.vertx.ext.auth.ecdsa;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

public interface EcdsaAuthCache {
    public void getChallenge(int userId, Handler<AsyncResult<String>> handler);
}
