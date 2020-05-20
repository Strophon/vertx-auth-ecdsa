package io.vertx.ext.auth.ecdsa;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import com.fasterxml.jackson.core.type.TypeReference;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.core.shareddata.impl.ClusterSerializable;
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;

public abstract class EcdsaUser extends AbstractUser implements ClusterSerializable {
    protected AuthProvider authProvider;
    protected EcdsaUserData user;
    protected String challenge;

    public EcdsaUser() { }

    public EcdsaUser(EcdsaUserData user, String challenge) {
        this.user = user;
        this.challenge = challenge;
    }

    @Override
    public JsonObject principal() {
        return new JsonObject().put("user", Json.encode(user)).put("challenge", challenge);
    }

    @Override
    public void setAuthProvider(AuthProvider authProvider) {
        this.authProvider = authProvider;
    }

    @Override
    protected void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
        Set<String> authorities = Json.decodeValue(
                                        user.getAuthorities(), new TypeReference<Set<String>>(){});
        permission = permission.toUpperCase();
        resultHandler.handle(Future.succeededFuture(authorities.contains(permission)));
    }

    @Override
    public void writeToBuffer(Buffer buff) {
        writeUserData(buff);
        super.writeToBuffer(buff);
    }

    @Override
    public int readFromBuffer(int pos, Buffer buffer) {
        pos = readUserData(buffer, pos);
        pos = super.readFromBuffer(pos, buffer);
        return pos;
    }

    private void writeUserData(Buffer buff) {
        String userJson = user == null ? null : Json.encode(user);
        writeString(userJson, buff);
        writeString(challenge, buff);
    }

    private int readUserData(Buffer buffer, int pos) {
        StringBuilder sb = new StringBuilder();

        pos = readString(buffer, pos, sb);
        user = sb.length() == 0 ? null : userFromJson(sb.toString());

        sb.setLength(0);

        pos = readString(buffer, pos, sb);
        challenge = sb.length() == 0 ? null : sb.toString();

        return pos;
    }

    private void writeString(String str, Buffer buff) {
        if (str != null) {
            byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
            buff.appendInt(bytes.length).appendBytes(bytes);
        } else {
            buff.appendInt(0);
        }
    }

    private int readString(Buffer buffer, int pos, StringBuilder sb) {
        int len = buffer.getInt(pos);
        pos += 4;

        byte[] bytes = buffer.getBytes(pos, pos + len);
        pos += len;

        sb.append(new String(bytes, StandardCharsets.UTF_8));

        return pos;
    }

    // requires knowledge of EcdsaUserData implementation to implement
    protected abstract EcdsaUserData userFromJson(String userJson);

}
