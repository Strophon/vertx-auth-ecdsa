package io.vertx.ext.auth.ecdsa;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;

import java.security.SignatureException;

import org.bitcoinj.core.ECKey;

public class EcdsaAuthProvider implements AuthProvider {
    public static final String USER_ID_PARAM = "userId";
    public static final String CHALLENGE_PARAM = "challenge";
    public static final String SIGNATURE_PARAM = "signature";

    private Vertx vertx;
    private EcdsaAuthCache cache;
    private EcdsaUserRetriever retriever;

    public EcdsaAuthProvider(Vertx vertx, EcdsaAuthCache cache, EcdsaUserRetriever retriever) {
        this.vertx = vertx;
        this.cache = cache;
        this.retriever = retriever;
    }

    @Override
    public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
        Integer userId;
        String challenge;
        String signature;
        try {
            userId = authInfo.getInteger(USER_ID_PARAM);
            challenge = authInfo.getString(CHALLENGE_PARAM);
            signature = authInfo.getString(SIGNATURE_PARAM);
        } catch(ClassCastException e) {
            resultHandler.handle(Future.failedFuture("Invalid auth info format"));
            return;
        }

        if(userId == null || challenge == null || signature == null) {
            resultHandler.handle(Future.failedFuture("Missing auth info"));
            return;
        }

        // first verify that the presented challenge matches the one stored in cache
        cache.getChallenge(userId, res -> {
            if(res.succeeded() && res.result() != null) {
                if(secureEquals(res.result(), challenge)) {
                    // next, get user from DB and verify signature
                    vertx.<EcdsaUser>executeBlocking(future -> {
                        EcdsaUserData userData = retriever.getUserData(userId);

                        boolean authenticated = false;

                        try {
                            ECKey.fromPublicOnly(userData.getPubkey())
                                    .verifyMessage(challenge, signature);
                            authenticated = true;
                        } catch(SignatureException | NullPointerException e) {
                            // verifyMessage() throws a SignatureException if sig invalid

                            // NPE indicates either challenge/signature not provided,
                            // or user/pubkey is null
                        }

                        if(authenticated) {
                            future.complete(
                                    retriever.getAuthorizedUser(userData, challenge));
                        } else {
                            future.fail("Authentication failed");
                        }
                    },
                    false, // not ordered
                    blockingResult -> {
                        if(blockingResult.succeeded()) {
                            resultHandler.handle(
                                    Future.succeededFuture(blockingResult.result()));
                        } else {
                            resultHandler.handle(
                                    Future.failedFuture("Authentication failed."));
                        }
                    });
                } else {
                    resultHandler.handle(Future.failedFuture("Authentication failed."));
                }
            } else {
                resultHandler.handle(Future.failedFuture(res.cause()));
            }
        });
    }

    public static boolean secureEquals(String ours, String theirs) {
        // prevents information leakage due to more-equal values taking longer to compare
        boolean result = ours.length() == theirs.length();
        int i = 0;
        for( ; i < ours.length(); i++) {
			result &= ours.charAt(i) == theirs.charAt(i % theirs.length());
		}

        if(i != ours.length()) {
			throw new RuntimeException("Compiler got sneaky!");
		}

        return result;
    }

}
