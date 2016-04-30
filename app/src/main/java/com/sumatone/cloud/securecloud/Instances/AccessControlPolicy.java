package com.sumatone.cloud.securecloud.Instances;

import android.text.TextUtils;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.Serializable;
import java.util.List;

/**
 * Created by Prince Bansal Local on 22-01-2016.
 */
public class AccessControlPolicy implements Serializable {

    private String role;
    private List<String> actions;

    public AccessControlPolicy() {
    }

    public AccessControlPolicy(String role, List<String> actions) {
        this.role = role;
        this.actions = actions;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public List<String> getActions() {
        return actions;
    }

    public void setActions(List<String> actions) {
        this.actions = actions;
    }

    public JSONObject toJson() throws JSONException {
        JSONObject object = new JSONObject();
        if (!TextUtils.isEmpty(role) && actions != null) {
            object.put("role", role);
            JSONArray actionJsonArray = new JSONArray();
            for (int j = 0; j < actions.size(); j++)
                actionJsonArray.put(actions.get(j));
            object.put("actions",actionJsonArray);
        }
        return object;

    }
}
