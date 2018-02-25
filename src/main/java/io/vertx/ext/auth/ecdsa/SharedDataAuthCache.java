package io.vertx.ext.auth.ecdsa;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;

public class SharedDataAuthCache implements EcdsaAuthCache {
    private static final String MAP_NAME = "challenges";
    private Vertx vertx;

    public SharedDataAuthCache(Vertx vertx) {
        this.vertx = vertx;
    }

    @Override
    public void getChallenge(int userId, Handler<AsyncResult<String>> handler) {
        vertx.sharedData().<Integer, String>getClusterWideMap(MAP_NAME, res -> {
            if(res.succeeded()) {
                res.result().get(userId, handler);
            } else {
                handler.handle(Future.failedFuture(res.cause()));
            }
        });
    }

    public void setChallenge(int userId, String challenge, Handler<AsyncResult<Void>> handler) {
        vertx.sharedData().<Integer, String>getClusterWideMap(MAP_NAME, res -> {
            if(res.succeeded()) {
                res.result().put(userId, challenge, handler);
            } else {
                handler.handle(Future.failedFuture(res.cause()));
            }
        });
    }

    public void removeChallenge(int userId, Handler<AsyncResult<String>> handler) {
        vertx.sharedData().<Integer, String>getClusterWideMap(MAP_NAME, res -> {
            if(res.succeeded()) {
                res.result().remove(userId, handler);
            } else {
                handler.handle(Future.failedFuture(res.cause()));
            }
        });
    }
}
