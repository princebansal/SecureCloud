package com.sumatone.cloud.securecloud.Instances;

import android.util.Base64;
import android.util.Log;
import android.util.Xml;

import org.apache.http.util.EncodingUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Prince Bansal Local on 23-01-2016.
 */
public class SecurityToken {

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    private int level;
    private String securityId;
    private List<String> fileId;
    private List<String> originalFileNames;
    private List<List<String>> accessRights;
    private String signature;

    public SecurityToken() {
    }

    public int getLevel() {
        return level;
    }

    public void setLevel(int level) {
        this.level = level;
    }

    public String getSecurityId() {
        return securityId;
    }

    public void setSecurityId(String securityId) {
        this.securityId = securityId;
    }

    public List<String> getFileId() {
        return fileId;
    }

    public void setFileId(List<String> fileId) {
        this.fileId = fileId;
    }

    public List<List<String>> getAccessRights() {
        return accessRights;
    }

    public void setAccessRights(List<List<String>> accessRights) {
        this.accessRights = accessRights;
    }

    public String getSignature() {
        return signature.replace("\\","").trim();
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public List<String> getOriginalFileNames() {
        return originalFileNames;
    }

    public void setOriginalFileNames(List<String> originalFileNames) {
        this.originalFileNames = originalFileNames;
    }

    public void decode(JSONObject tokenObject) throws JSONException {
        setLevel(tokenObject.getInt("level"));
        setSecurityId(tokenObject.getString("sid"));
        setSignature(tokenObject.getString("HMAC"));
        fileId = new ArrayList<>();
        JSONArray fileJsonArray = tokenObject.getJSONArray("fids");
        for (int i = 0; i < fileJsonArray.length(); i++) {
            fileId.add(fileJsonArray.getString(i));
        }

        originalFileNames = new ArrayList<>();
        JSONArray orFileJsonArray = tokenObject.getJSONArray("ofids");
        for (int i = 0; i < orFileJsonArray.length(); i++) {
            originalFileNames.add(orFileJsonArray.getString(i));
        }

        accessRights = new ArrayList<>();
        JSONArray actionsJsonArray = tokenObject.getJSONArray("actions");

        for (int j = 0; j < actionsJsonArray.length(); j++) {
            List<String> action = new ArrayList<>();
            JSONArray jsonArray = actionsJsonArray.getJSONArray(j);
            for (int i = 0; i < jsonArray.length(); i++) {
                action.add(jsonArray.getString(i));
            }
            accessRights.add(action);
        }
    }

    public static String calculateRFC2104HMAC(String data, String key)
            throws java.security.SignatureException {
        String result;
        try {

            // get an hmac_sha1 key from the raw key bytes
            SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);

            // get an hmac_sha1 Mac instance and initialize with the signing key
            Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            mac.init(signingKey);

            // compute the hmac on input data bytes
            byte[] rawHmac = mac.doFinal(data.getBytes("UTF-8"));

            // base64-encode the hmac
            result = Base64.encodeToString(rawHmac,Base64.DEFAULT);
            Log.d("hmacjava",result);

        } catch (Exception e) {
            throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
        }
        return result.trim();
    }

    public String getSignatureData(String response) throws JSONException {
        JSONObject object=new JSONObject(response);

        object.remove("HMAC");


        return object.toString().trim();
    }
}
