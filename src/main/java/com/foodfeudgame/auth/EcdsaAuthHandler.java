package com.foodfeudgame.auth;

import java.util.Base64;

import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.impl.AuthHandlerImpl;

public class EcdsaAuthHandler extends AuthHandlerImpl {

	public EcdsaAuthHandler(AuthProvider authProvider) {
		super(authProvider);
		boolean isEcdsa = authProvider instanceof EcdsaAuthProvider;
		if(!isEcdsa)
			throw new IllegalArgumentException("Must pass in an instance of EcdsaAuthProvider");
	}

	@Override
	public void handle(RoutingContext context) {
		User user = context.user();
		if (user != null) {
			// Already authenticated in, just authorize
			authorise(user, context);
		} else {
			HttpServerRequest request = context.request();
			String authorization = request.headers().get(HttpHeaders.AUTHORIZATION);
			
			if (authorization == null) {
				context.fail(401);
				return;
			}
			try {
				String decoded = new String(Base64.getDecoder().decode(authorization));
				String[] parts = decoded.split(" ");
				
				int userId = Integer.parseInt(parts[0]);
				String challenge = parts[1];
				String signature = parts[2];

				EcdsaAuthProvider eap = (EcdsaAuthProvider) authProvider;
				
				JsonObject authInfo = new JsonObject().put(eap.getUserIdParam(), userId)
						.put(eap.getChallengeParam(), challenge)
						.put(eap.getSignatureParam(), signature);

				authProvider.authenticate(authInfo, res -> {
					if (res.succeeded()) {
						User authenticated = res.result();
						context.setUser(authenticated);
						authorise(authenticated, context);
					} else {
						context.fail(401);
					}
				});
			} catch (ArrayIndexOutOfBoundsException e) {
				context.fail(401);
				return;
			} catch (IllegalArgumentException | NullPointerException e) {
				context.fail(e);
				return;
			}
		}
	}
}
