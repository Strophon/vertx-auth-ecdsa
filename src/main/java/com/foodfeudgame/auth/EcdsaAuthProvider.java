package com.foodfeudgame.auth;

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
	private static final String DEFAULT_USER_ID_PARAM = "userId";
	private static final String DEFAULT_CHALLENGE_PARAM = "challenge";
	private static final String DEFAULT_SIGNATURE_PARAM = "signature";

	private String userIdParam;
	private String challengeParam;
	private String signatureParam;
	private Vertx vertx;
	private EcdsaAuthCache cache;
	private EcdsaUserRetriever retriever;
	
	public EcdsaAuthProvider(Vertx vertx, EcdsaAuthCache cache, EcdsaUserRetriever retriever) {
		this.vertx = vertx;
		this.cache = cache;
		this.retriever = retriever;
		this.userIdParam = DEFAULT_USER_ID_PARAM;
		this.challengeParam = DEFAULT_CHALLENGE_PARAM;
		this.signatureParam = DEFAULT_SIGNATURE_PARAM;
	}
	
	public String getUserIdParam() {
		return userIdParam;
	}
	public EcdsaAuthProvider setUserIdParam(String userIdParam) {
		this.userIdParam = userIdParam;
		return this;
	}
	public String getChallengeParam() {
		return challengeParam;
	}
	public EcdsaAuthProvider setChallengeParam(String challengeParam) {
		this.challengeParam = challengeParam;
		return this;
	}
	public String getSignatureParam() {
		return signatureParam;
	}
	public EcdsaAuthProvider setSignatureParam(String signatureParam) {
		this.signatureParam = signatureParam;
		return this;
	}

	@Override
	public void authenticate(JsonObject authInfo, Handler<AsyncResult<User>> resultHandler) {
		Integer userId;
		String challenge;
		String signature;
		try {
			userId = authInfo.getInteger(userIdParam);
			challenge = authInfo.getString(challengeParam);
			signature = authInfo.getString(signatureParam);
		} catch(ClassCastException e) {
			resultHandler.handle(Future.failedFuture("Invalid auth info format"));
			return;
		}
		
		if(userId == null || challenge == null || signature == null) {
			resultHandler.handle(Future.failedFuture("Missing auth info"));
			return;
		}
		
		// first verify that the presented challenge matches the one stored in cache
		cache.getChallenge(userId.intValue(), res -> {
			if(res.succeeded() && res.result() != null) {
				if(secureEqualsIgnoreCase(res.result(), challenge)) {
					// next, get user from DB and verify signature
					vertx.<EcdsaUser>executeBlocking(
							future -> {
								EcdsaUserData userData = retriever.getUserData(userId);
								
								boolean authenticated = false;

								try { // verifyMessage() throws a SignatureException if sig invalid
									ECKey.fromPublicOnly(userData.getPubkey())
											.verifyMessage(challenge, signature);
									authenticated = true;
								} catch(SignatureException e) { // catch sig exceptions, NPEs
								} catch(NullPointerException e) {
								}  // do nothing if exception thrown

								if(authenticated) {
									future.complete(
											retriever.getAuthorizedUser(userData));
								} else {
									future.fail("Auth failed");
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
	
	private static boolean secureEqualsIgnoreCase(String ours, String theirs) {
		// prevents information leakage due to more-equal values taking longer to compare
		ours = ours.toUpperCase();
		theirs = theirs.toUpperCase();
		
		boolean result = ours.length() == theirs.length();
		int i = 0;
		for(i = 0; i < ours.length(); i++)
			result &= ours.charAt(i) == theirs.charAt(i % theirs.length());
		
		if(i != ours.length())
			throw new RuntimeException("Compiler got sneaky!");
		
		return result;
	}

}
