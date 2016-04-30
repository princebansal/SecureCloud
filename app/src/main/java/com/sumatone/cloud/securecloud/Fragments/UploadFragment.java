/*
 * Copyright (c) 2015 GDG VIT Vellore.
 * This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.sumatone.cloud.securecloud.Fragments;

import android.app.AlertDialog;
import android.content.ContentUris;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.preference.PreferenceManager;
import android.provider.DocumentsContract;
import android.provider.MediaStore;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.text.TextUtils;
import android.util.Log;
import android.util.SparseBooleanArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.android.volley.AuthFailureError;
import com.android.volley.DefaultRetryPolicy;
import com.android.volley.Request;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;
import com.sumatone.cloud.securecloud.Boundary.AppController;
import com.sumatone.cloud.securecloud.Control.Ciphers;
import com.sumatone.cloud.securecloud.Control.PrimeGenerator;
import com.sumatone.cloud.securecloud.Instances.AccessControlPolicy;
import com.sumatone.cloud.securecloud.Instances.PolicyConfiguration;
import com.sumatone.cloud.securecloud.R;
import com.sumatone.cloud.securecloud.Activities.RegisterActivity;
import com.sumatone.cloud.securecloud.Boundary.UploadFile;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;



/**
 * Created by shalini on 28-06-2015.
 */
public class UploadFragment extends Fragment implements View.OnClickListener {

    public TextView fileName, progress, fileSize;
    public Button uploadButton, selectFile;
    private Uri fileUri = null;
    private static final String uploadUrl = "http://hbppac.cloudapp.net:8080/hbppacjava/upload.jsp";
    private static final String taUrl = "http://datacomm.azurewebsites.net/trustedAuthority.php";
    private String filePath;
    private ProgressBar uploadProgressBar;
    private String userName, level, role, nof;
    private JSONArray acpsArray = null;
    private BigInteger blindValue;
    private int state = 0;

    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        ViewGroup rootView = (ViewGroup) inflater.inflate(
                R.layout.upload_fragment, container, false);
        init(rootView);
        setInit();
        //setData();

        return rootView;
    }


    private void init(ViewGroup rootView) {
        fileName = (TextView) rootView.findViewById(R.id.file_name);
        progress = (TextView) rootView.findViewById(R.id.progress);
        uploadButton = (Button) rootView.findViewById(R.id.upload_button);
        selectFile = (Button) rootView.findViewById(R.id.select_file);
        fileSize = (TextView) rootView.findViewById(R.id.file_size);
        uploadProgressBar = (ProgressBar) rootView.findViewById(R.id.upload_progress_bar);


    }


    private void setInit() {
        uploadButton.setOnClickListener(this);
        selectFile.setOnClickListener(this);

        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(getActivity());
        userName = sharedPreferences.getString("email", "");
        level = String.valueOf(sharedPreferences.getInt("level", -1));
        role = sharedPreferences.getString("role", "");
        if (!userName.equals("") && !level.equals("-1") && !role.equals("")) {

            nof = userName + "_" + level + "_" + role;
        } else {
            nof = "null";
        }
    }

    private void encryptAndUpload(final JSONObject policy) {

        new AsyncTask<Void, Void, Map<String, Object>>() {

            @Override
            protected void onPreExecute() {
                super.onPreExecute();
                uploadProgressBar.setVisibility(ProgressBar.VISIBLE);
                progress.setText("Encrypting File");
            }

            @Override
            protected Map<String, Object> doInBackground(Void... params) {

                if (!TextUtils.isEmpty(filePath)) {
                    try {

                        File tempFile = new File(filePath);
                        byte[] fileBytes = new byte[(int) tempFile.length()];
                        FileInputStream fileInputStream = new FileInputStream(tempFile);
                        fileInputStream.read(fileBytes, 0, (int) tempFile.length());
                        PrimeGenerator primeGenerator = new PrimeGenerator(128, 1, new SecureRandom());
                        BigInteger[] result = primeGenerator.getSafePrimeAndGenerator();
                        Log.d("prime", result[0].toString());
                        Log.d("longprime", String.valueOf(result[0].longValue()));
                        Log.d("generator", result[1].toString());
                        blindValue = result[0];

                        BigInteger relativePrime = result[0].subtract(BigInteger.valueOf(2));
                        //BigInteger nts=result[0].add(BigInteger.valueOf(1)).divide(BigInteger.valueOf(2));
                        long time = System.currentTimeMillis();
                        long afterTime;
                        //Log.d("inittime", String.valueOf(time));

                        byte[] enByte = Ciphers.pohligHellmanEncipher(fileBytes, relativePrime, result[0]);
                        afterTime = System.currentTimeMillis();
                        //Log.d("after enc", String.valueOf(afterTime));
                        Log.d("after enc diff", String.valueOf(afterTime - time));
                        time = System.currentTimeMillis();
                        String encipheredText = new String(enByte, "UTF-8");
                        Log.d("phEncipher", encipheredText);
                        /*byte[] deByte = Ciphers.pohligHellmanDecipher(enByte, result[0].subtract(BigInteger.valueOf(2)).modInverse(result[0].subtract(BigInteger.ONE)), result[0]);
                        Log.d("phDecipher", new String(deByte, "UTF-8"));
                        afterTime = System.currentTimeMillis();
                        Log.d("after dec", String.valueOf(afterTime));
                        Log.d("after diff ", String.valueOf(afterTime - time));
                        */
                        String orgName = tempFile.getName();
                        int hash = orgName.hashCode();
                        File f = new File(getActivity().getCacheDir(), nof + "_" + hash + "." + tempFile.getName().substring(tempFile.getName().lastIndexOf(".") + 1));
                        Log.d("newFileName", f.getName());
                        FileOutputStream fileOutputStream = new FileOutputStream(f);
                        fileOutputStream.write(enByte);
                        fileInputStream.close();
                        fileOutputStream.close();
                        Map<String, Object> content = new HashMap<String, Object>();
                        content.put("file", f);
                        content.put("originalName", orgName);
                        return content;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    return null;

                }

                return null;
            }

            @Override
            protected void onPostExecute(Map<String, Object> aVoid) {
                super.onPostExecute(aVoid);

                if (aVoid == null || blindValue == null) {
                    uploadProgressBar.setVisibility(View.GONE);
                    progress.setText("Error");
                } else {

                    informTrustedAuthority((File) aVoid.get("file"), blindValue, (String) aVoid.get("originalName"),policy);

                }

            }
        }.execute();
    }

    private void informTrustedAuthority(final File aVoid, final BigInteger blindValue, final String originalName, final JSONObject policy) {
        uploadProgressBar.setVisibility(View.VISIBLE);
        progress.setText("Informing TA");
        selectFile.setEnabled(false);
        uploadButton.setEnabled(false);

        StringRequest stringRequest = new StringRequest(Request.Method.POST, taUrl,
                new Response.Listener<String>() {
                    @Override
                    public void onResponse(String response) {
                        Log.d("response", response);
                        showMessage(response);
                        uploadProgressBar.setVisibility(View.GONE);
                        progress.setText("TA responded");
                        if (response.equals("exist")) {
                            showMessage("TA responded");
                            progress.setText("File already exist");

                            selectFile.setEnabled(true);
                            uploadButton.setEnabled(true);
                        } else if (response.equals("Error")) {
                            showMessage("Unknown Error");
                            progress.setText("Error");

                            selectFile.setEnabled(true);
                            uploadButton.setEnabled(true);
                        } else if (response.equals("success")) {
                            uploadFile(aVoid);
                        }
                    }

                }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                uploadProgressBar.setVisibility(View.GONE);
                progress.setText("Error Occured");
                showMessage(error.getMessage());
                error.printStackTrace();
                selectFile.setEnabled(true);
                uploadButton.setEnabled(true);
            }
        }) {
            @Override
            protected Map<String, String> getParams() throws AuthFailureError {
                Map postParams = new HashMap<String, String>();
                postParams.put("filename", aVoid.getName());
                postParams.put("acps", policy.toString());
                postParams.put("unblind", blindValue.toString());
                postParams.put("originalName", originalName);
                postParams.put("uploaderLevel", String.valueOf(PreferenceManager.getDefaultSharedPreferences(getActivity()).getInt("level", 7)));
                postParams.put("uploaderId", PreferenceManager.getDefaultSharedPreferences(getActivity()).getString("email", ""));
                return postParams;
            }
        };

        stringRequest.setRetryPolicy(new DefaultRetryPolicy(5000, 2, 2));
        AppController.getInstance().addToRequestQueue(stringRequest);

    }

    @Override
    public void onResume() {
        super.onResume();
    }


    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.upload_button:
                selectAcps();
                break;
            case R.id.select_file:
                chooseFile();

                break;
        }
    }

    private void selectAcps() {
        final CharSequence[] items = RegisterActivity.ROLES;
        int level = PreferenceManager.getDefaultSharedPreferences(getActivity()).getInt("level", 7);
        int levelBelowThisUser = searchLastLevel(RegisterActivity.LEVELS, level);
        final CharSequence[] filterItems = Arrays.copyOfRange(items, levelBelowThisUser + 1, items.length);

        final AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
        builder.setTitle("Who can download the file?");
        builder.setMultiChoiceItems(filterItems, null, null);

        final List<AccessControlPolicy> tempList = new ArrayList<AccessControlPolicy>();

        builder.setPositiveButton("Next", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int id) {
                switch (state) {
                    case 0:
                        SparseBooleanArray CheCked = ((AlertDialog) dialog).getListView().getCheckedItemPositions();
                        acpsArray = new JSONArray();
                        for (int i = 0; i < CheCked.size(); i++) {
                            if (CheCked.get(i) == true) {
                                List<String> actionList = new ArrayList<String>();
                                actionList.add("download");
                                tempList.add(new AccessControlPolicy(filterItems[i].toString(),actionList));
                                /*JSONObject object = new JSONObject();
                                try {
                                    object.put(String.valueOf(RegisterActivity.LEVELS[i]), "download");
                                    acpsArray.put(object);
                                } catch (JSONException e) {
                                    e.printStackTrace();
                                }*/
                            }
                        }
                        state = 1;
                        builder.setTitle("Who can delete the file?");
                        builder.setMultiChoiceItems(filterItems, null, null);
                        builder.create().show();

                        //encryptAndUpload();
                        break;
                    case 1:
                        CheCked = ((AlertDialog) dialog).getListView().getCheckedItemPositions();
                        acpsArray = new JSONArray();
                        for (int i = 0; i < CheCked.size(); i++) {
                            if (CheCked.get(i) == true) {
                                for (int j = 0; j < tempList.size(); j++) {
                                    if (tempList.get(j).getRole().equals(filterItems[i].toString())) {
                                        tempList.get(j).getActions().add("delete");
                                        break;
                                    }
                                }
                                /*JSONObject object = new JSONObject();
                                try {
                                    object.put(String.valueOf(RegisterActivity.LEVELS[i]), "download");
                                    acpsArray.put(object);
                                } catch (JSONException e) {
                                    e.printStackTrace();
                                }*/
                            }
                        }
                        state = 2;
                        builder.setTitle("Who can update the file?");
                        builder.setMultiChoiceItems(filterItems, null, null);
                        builder.create().show();
                        break;
                    case 2:
                        state=0;
                        CheCked = ((AlertDialog) dialog).getListView().getCheckedItemPositions();
                        acpsArray = new JSONArray();
                        for (int i = 0; i < CheCked.size(); i++) {
                            if (CheCked.get(i) == true) {
                                for (int j = 0; j < tempList.size(); j++) {
                                    if (tempList.get(j).getRole().equals(filterItems[i].toString())) {
                                        tempList.get(j).getActions().add("update");
                                        break;
                                    }
                                }
                                /*JSONObject object = new JSONObject();
                                try {
                                    object.put(String.valueOf(RegisterActivity.LEVELS[i]), "download");
                                    acpsArray.put(object);
                                } catch (JSONException e) {
                                    e.printStackTrace();
                                }*/
                            }
                        }
                        formPolicyConfigurations(tempList);
                        break;
                    default:
                }
            }
        });
        builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int id) {
                dialog.cancel();
            }
        });
        builder.create().show();
    }

    private void formPolicyConfigurations(List<AccessControlPolicy> tempList) {
        PolicyConfiguration policyConfiguration = new PolicyConfiguration(new ArrayList<AccessControlPolicy>(),
                new ArrayList<AccessControlPolicy>(), new ArrayList<AccessControlPolicy>());

        for (int i = 0; i < tempList.size(); i++) {
            AccessControlPolicy policy = tempList.get(i);
            if (policy.getActions().contains("download")) ;
            policyConfiguration.getDownloadList().add(policy);

            if (policy.getActions().contains("delete")) ;
            policyConfiguration.getDeleteList().add(policy);

            if (policy.getActions().contains("update")) ;
            policyConfiguration.getUpdateList().add(policy);


        }

        try {
            encryptAndUpload(policyConfiguration.toJson());
        } catch (JSONException e) {


        }
    }

    private int searchLastLevel(int[] levels, int level) {
        for (int i = 0; i < levels.length; i++) {
            if (levels.length - i - 1 == level) {
                return levels.length - i - 1;
            }
        }
        return levels.length - 1;
    }

    private void uploadFile(File aVoid) {

        if (!TextUtils.isEmpty(filePath)) {

            uploadProgressBar.setVisibility(View.VISIBLE);
            progress.setText("Uploading");

            File fileToUpload = aVoid;
            HashMap<String, String> map = new HashMap<>();
            map.put("submit", "Submit");
            map.put("level", level);
            selectFile.setEnabled(false);
            uploadButton.setEnabled(false);
            String newUploadUrl = uploadUrl + "?level=" + level;
            UploadFile uploadFile = new UploadFile(newUploadUrl, new Response.ErrorListener() {
                @Override
                public void onErrorResponse(VolleyError error) {
                    error.printStackTrace();
                    uploadProgressBar.setVisibility(View.GONE);
                    progress.setText("Upload Error");
                    showMessage("Error uploading");
                    selectFile.setEnabled(true);
                    uploadButton.setEnabled(true);
                }
            }, new Response.Listener<String>() {
                @Override
                public void onResponse(String response) {
                    Log.d("response", response);
                    showMessage(response);
                    uploadProgressBar.setVisibility(View.GONE);
                    progress.setText("Successfully Uploaded");
                }
            }, fileToUpload, fileToUpload.length(), map, null, "fileToUpload", new UploadFile.MultipartProgressListener() {
                @Override
                public void transferred(final long transfered, final int prog) {
                    getActivity().runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            // progress.setText(String.valueOf(transfered));
                            /*if (prog == 100) {
                                progress.setText("Completed");
                                selectFile.setEnabled(true);
                                uploadButton.setEnabled(true);
                            }*/
                        }
                    });
                }
            });
            uploadFile.setRetryPolicy(new DefaultRetryPolicy(30000, 1, 1));
            AppController.getInstance().addToRequestQueue(uploadFile);
        } else {
            showMessage("Error fetching file");
            uploadProgressBar.setVisibility(View.GONE);
            progress.setText("Error");
        }

    }

    private void showMessage(String s) {
        Toast.makeText(getActivity(), s, Toast.LENGTH_SHORT).show();
    }

    private void chooseFile() {
        Intent intent = new Intent();

        intent.setType("*/*");
        intent.setAction(Intent.ACTION_GET_CONTENT);
        startActivityForResult(Intent.createChooser(intent, "Complete action using"), 0);

    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        Log.d("calledf", String.valueOf(requestCode));
        if (requestCode == 0) {
            if (resultCode == getActivity().RESULT_OK) {
                Uri selectedPdfUri = data.getData();
                fileUri = selectedPdfUri;
                Log.d("pdfuri", selectedPdfUri.toString());
                try {
                    filePath = getPath(getActivity(), selectedPdfUri);
                    Log.d("filePath", getPath(getActivity(), selectedPdfUri));
                } catch (Exception e) {
                    e.printStackTrace();
                }

                if (filePath != null) {
                    File f = new File(filePath);
                    fileName.setText(f.getName());
                    fileSize.setText(String.valueOf(f.length()));
                }
            }
        }
    }


    /**
     * Get a file path from a Uri. This will get the the path for Storage Access
     * Framework Documents, as well as the _data field for the MediaStore and
     * other file-based ContentProviders.
     *
     * @param context The context.
     * @param uri     The Uri to query.
     * @author paulburke
     */

    public static String getPath(final Context context, final Uri uri) {

        final boolean isKitKat = Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT;


        // DocumentProvider
        if (isKitKat && DocumentsContract.isDocumentUri(context, uri)) {
            // ExternalStorageProvider
            if (isExternalStorageDocument(uri)) {
                final String docId = DocumentsContract.getDocumentId(uri);
                Log.d("isKitkat-isExt", docId);
                final String[] split = docId.split(":");
                final String type = split[0];

                if ("primary".equalsIgnoreCase(type)) {
                    return Environment.getExternalStorageDirectory() + "/" + split[1];
                }

                // TODO handle non-primary volumes
            }
            // DownloadsProvider
            else if (isDownloadsDocument(uri)) {

                final String id = DocumentsContract.getDocumentId(uri);

                Log.d("isKitkat-isDownload", id);
                final Uri contentUri = ContentUris.withAppendedId(
                        Uri.parse("content://downloads/public_downloads"), Long.valueOf(id));

                return getDataColumn(context, contentUri, null, null);
            }
            // MediaProvider
            else if (isMediaDocument(uri)) {
                final String docId = DocumentsContract.getDocumentId(uri);
                Log.d("isKitkat-isMedia", docId);
                final String[] split = docId.split(":");
                final String type = split[0];

                Uri contentUri = null;
                if ("image".equals(type)) {
                    contentUri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
                } else if ("video".equals(type)) {
                    contentUri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI;
                } else if ("audio".equals(type)) {
                    contentUri = MediaStore.Audio.Media.EXTERNAL_CONTENT_URI;
                }

                final String selection = "_id=?";
                final String[] selectionArgs = new String[]{
                        split[1]
                };

                return getDataColumn(context, contentUri, selection, selectionArgs);
            }
        }
        // MediaStore (and general)
        else if ("content".equalsIgnoreCase(uri.getScheme())) {


            // Return the remote address
            if (isGooglePhotosUri(uri)) {
                Log.d("isGPhoto", String.valueOf(uri));
                return uri.getLastPathSegment();
            }

            return getDataColumn(context, uri, null, null);
        }
        // File
        else if ("file".equalsIgnoreCase(uri.getScheme())) {
            return uri.getPath();
        }

        return null;
    }

    /**
     * Get the value of the data column for this Uri. This is useful for
     * MediaStore Uris, and other file-based ContentProviders.
     *
     * @param context       The context.
     * @param uri           The Uri to query.
     * @param selection     (Optional) Filter used in the query.
     * @param selectionArgs (Optional) Selection arguments used in the query.
     * @return The value of the _data column, which is typically a file path.
     */
    public static String getDataColumn(Context context, Uri uri, String selection,
                                       String[] selectionArgs) {

        Cursor cursor = null;
        final String column = "_data";
        final String[] projection = {
                column
        };

        try {
            cursor = context.getContentResolver().query(uri, projection, selection, selectionArgs,
                    null);
            if (cursor != null && cursor.moveToFirst()) {
                final int index = cursor.getColumnIndexOrThrow(column);
                return cursor.getString(index);
            }
        } finally {
            if (cursor != null)
                cursor.close();
        }
        return null;
    }


    /**
     * @param uri The Uri to check.
     * @return Whether the Uri authority is ExternalStorageProvider.
     */
    public static boolean isExternalStorageDocument(Uri uri) {
        return "com.android.externalstorage.documents".equals(uri.getAuthority());
    }

    /**
     * @param uri The Uri to check.
     * @return Whether the Uri authority is DownloadsProvider.
     */
    public static boolean isDownloadsDocument(Uri uri) {
        return "com.android.providers.downloads.documents".equals(uri.getAuthority());
    }

    /**
     * @param uri The Uri to check.
     * @return Whether the Uri authority is MediaProvider.
     */
    public static boolean isMediaDocument(Uri uri) {
        return "com.android.providers.media.documents".equals(uri.getAuthority());
    }

    /**
     * @param uri The Uri to check.
     * @return Whether the Uri authority is Google Photos.
     */
    public static boolean isGooglePhotosUri(Uri uri) {
        return "com.google.android.apps.photos.content".equals(uri.getAuthority());
    }
}