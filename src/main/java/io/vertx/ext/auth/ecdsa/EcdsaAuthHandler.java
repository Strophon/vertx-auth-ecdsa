package io.vertx.ext.auth.ecdsa;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.impl.AuthHandlerImpl;

import java.util.Base64;

public class EcdsaAuthHandler extends AuthHandlerImpl {

	public EcdsaAuthHandler(AuthProvider authProvider) {
		super(authProvider);
		boolean isEcdsa = authProvider instanceof EcdsaAuthProvider;
		if(!isEcdsa)
			throw new IllegalArgumentException("Must pass in an instance of EcdsaAuthProvider");
	}

	@Override
	public void parseCredentials(RoutingContext context,
										Handler<AsyncResult<JsonObject>> handler) {
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
			
			handler.handle(Future.succeededFuture(authInfo));
		} catch (ArrayIndexOutOfBoundsException e) {
			context.fail(401);
			return;
		} catch (IllegalArgumentException | NullPointerException e) {
			context.fail(e);
			return;
		}
	}
}
