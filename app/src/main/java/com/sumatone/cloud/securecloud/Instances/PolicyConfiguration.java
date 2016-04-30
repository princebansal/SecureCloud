package com.sumatone.cloud.securecloud.Instances;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.Serializable;
import java.util.List;

/**
 * Created by Prince Bansal Local on 22-01-2016.
 */
public class PolicyConfiguration implements Serializable {

    private List<AccessControlPolicy> downloadList;
    private List<AccessControlPolicy> deleteList;
    private List<AccessControlPolicy> updateList;

    public PolicyConfiguration(List<AccessControlPolicy> downloadList, List<AccessControlPolicy> deleteList, List<AccessControlPolicy> updateList) {
        this.downloadList = downloadList;
        this.deleteList = deleteList;
        this.updateList = updateList;
    }

    public List<AccessControlPolicy> getDownloadList() {
        return downloadList;
    }

    public void setDownloadList(List<AccessControlPolicy> downloadList) {
        this.downloadList = downloadList;
    }

    public List<AccessControlPolicy> getDeleteList() {
        return deleteList;
    }

    public void setDeleteList(List<AccessControlPolicy> deleteList) {
        this.deleteList = deleteList;
    }

    public List<AccessControlPolicy> getUpdateList() {
        return updateList;
    }

    public void setUpdateList(List<AccessControlPolicy> updateList) {
        this.updateList = updateList;
    }

    public JSONObject toJson() throws JSONException {
        JSONObject root = new JSONObject();
        root.put("download", new JSONArray());
        root.put("delete", new JSONArray());
        root.put("update", new JSONArray());

        for (int i = 0; i < downloadList.size(); i++) {
            root.getJSONArray("download").put(downloadList.get(i).toJson());
        }

        for (int i = 0; i < deleteList.size(); i++) {
            root.getJSONArray("delete").put(deleteList.get(i).toJson());
        }

        for (int i = 0; i < updateList.size(); i++) {
            root.getJSONArray("update").put(updateList.get(i).toJson());
        }

        return root;
    }
}
