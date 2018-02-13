
package com.github.zmatsuo.pageantp_android;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Message;
import android.preference.PreferenceManager;
import android.support.annotation.NonNull;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import com.obsez.android.lib.filechooser.ChooserDialog;

import java.io.File;
import java.lang.ref.WeakReference;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import static com.github.zmatsuo.pageantp_android.Sign.generateKeyPair;
import static com.github.zmatsuo.pageantp_android.Sign.getFingerprintSHA256Base64;
import static com.github.zmatsuo.pageantp_android.Sign.getPrivateKey;
import static com.github.zmatsuo.pageantp_android.Sign.getPublicKey;
import static com.github.zmatsuo.pageantp_android.Sign.showPrivateKey;
import static com.github.zmatsuo.pageantp_android.Sign.showPublicKey;

public class MainActivity extends AppCompatActivity implements IPagent {

    private static final String TAG = "MainActivity";

    // Intent request codes
    private static final int REQUEST_CONNECT_DEVICE_SECURE = 1;
    private static final int REQUEST_CONNECT_DEVICE_INSECURE = 2;
    private static final int REQUEST_ENABLE_BT = 3;
    private static final int REQUEST_READ_STORAGE_PERMISSION = 4;
    private static final int REQUEST_SETTING = 5;

    private SharedPreferences mPref;
    private BluetoothAdapter mBluetoothAdapter = null;
    private KeyguardManager mKeyguardManager;

    private TextView mComStateText;
    private BluetoothChatService mChatService;
    ArrayList<String> listItems;
    ArrayAdapter<String> arrayAdapter;

    private String mConnectedDeviceName = null;

    KeyStoreTest kst = new KeyStoreTest();
    Pagent mPagent;

    private LocalHandler mHandler = new LocalHandler(this);

    public void message(String s) {
        arrayAdapter.add(s);
    }

    public void write(final byte[] data) {
        mChatService.write(data);
    }

    private void btEnable(boolean enable) {
        if (enable) {
            findViewById(R.id.connect_button).setEnabled(true);
        } else {
            findViewById(R.id.connect_button).setEnabled(false);
        }
    }

    private class LocalHandler extends Handler {
        private final WeakReference<MainActivity> mActivity;

        public LocalHandler(MainActivity mainActivity) {
            mActivity = new WeakReference<MainActivity>(mainActivity);
        }

        @Override
        public void handleMessage(Message msg) {
//            FragmentActivity activity = getActivity();
            switch (msg.what) {
            case Constants.MESSAGE_STATE_CHANGE:
                switch (msg.arg1) {
                case BluetoothChatService.STATE_CONNECTED:
                    mComStateText.setText("connect");
                    Toast.makeText(MainActivity.this, "connect", Toast.LENGTH_LONG).show();
                    //setStatus(getString(R.string.title_connected_to, mConnectedDeviceName));
                    //mConversationArrayAdapter.clear();
                    arrayAdapter.add("connect");
                    break;
                case BluetoothChatService.STATE_CONNECTING:
                    mComStateText.setText("connecting...!");
                    arrayAdapter.add("connecting..");
//                    Toast.makeText(this, "connect", Toast.LENGTH_LONG).show();
//                    setStatus(R.string.title_connecting);
                    break;
                case BluetoothChatService.STATE_LISTEN:
                    mComStateText.setText("listening...!");
                    arrayAdapter.add("listening..");
                    break;
                case BluetoothChatService.STATE_NONE:
                    mComStateText.setText("bt none");
                    arrayAdapter.add("bt none");
//                    setStatus(R.string.title_not_connected);
                    break;
                }
                break;
            case Constants.MESSAGE_WRITE: {
                byte[] writeBuf = (byte[]) msg.obj;
                // construct a string from the buffer
                String writeMessage = new String(writeBuf);
                //mConversationArrayAdapter.add("Me:  " + writeMessage);
                String s = "bt send " + writeBuf.length + "bytes";
                Log.d(TAG, s);
                arrayAdapter.add(s);
                break;
            }
            case Constants.MESSAGE_READ: {
                final byte[] readBuf = (byte[]) msg.obj;
                mPagent.message_read(readBuf);
                break;
            }
            case Constants.MESSAGE_CONNECT_TO:
            case Constants.MESSAGE_CONNECT_FROM: {
                // save the connected device's name
                mConnectedDeviceName = msg.getData().getString(Constants.DEVICE_NAME);
                String adr = msg.getData().getString(Constants.DEVICE_ADDRESS);

                String s;
                if (msg.what == Constants.MESSAGE_CONNECT_TO) {
                    s = "connect to ";
                } else {
                    s = "connect from ";
                }
                s += mConnectedDeviceName + "(" + adr + ")";

                arrayAdapter.add(s);
                break;
            }
            case Constants.MESSAGE_TOAST: {
                String s = msg.getData().getString(Constants.TOAST);
                Toast.makeText(MainActivity.this, s,
                               Toast.LENGTH_SHORT).show();
                arrayAdapter.add("toast " + s);
                break;
            }
            case Constants.MESSAGE_DISCONNECT: {
                arrayAdapter.add("disconnect");
                break;
            }
            default: {
                arrayAdapter.add("unhandled message " + msg.what);
                break;
            }
            }
        }
    }

    private void importPrivateKeyI() {
        // https://github.com/hedzr/android-file-chooser
        File pathExternalPublicDir =
            Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS);
        String path = pathExternalPublicDir.getAbsolutePath();
        new ChooserDialog().with(this)
            .withStartFile(path)
            .withChosenListener(new ChooserDialog.Result() {
                @Override
                public void onChoosePath(String path, File pathFile) {

                    arrayAdapter.clear();
                    arrayAdapter.add("import");
                    
                    String s;
                    s = "FILE: " + path;
                    arrayAdapter.add(s);

                    PrivateKey privateKey = getPrivateKey(path);
                    kst.importPrivateKey(privateKey);

                    listKey();

                    if (false) {
                        s = showPrivateKey(privateKey);
                        arrayAdapter.add(s);
                        s = getFingerprintSHA256Base64(privateKey);
                        arrayAdapter.add(s);
                        PublicKey publicKey = getPublicKey(privateKey);
                        s = showPublicKey(publicKey);
                        arrayAdapter.add(s);
                    }
                }
            })
            .build()
            .show();
    }

    private void importPrivateKey() {
        if (checkReadStragePermission() == false) {
                requestReadStragePermission();
        } else {
            importPrivateKeyI();
        }
    }

    private void removeKey() {
        // setup the alert builder
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Choose remove key");

        // add a checkbox list
        List<String> fingerprints = kst.getFingerPrints();
        final String [] fingerprintAry = fingerprints.toArray(new String[fingerprints.size()]);
        boolean [] checkedItems = new boolean[fingerprints.size()];
        builder.setItems(fingerprintAry, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                String fingerprint = fingerprintAry[which];
                System.out.println(String.format("%d: %s", which, fingerprint));
                kst.deleteKey(fingerprint);

                arrayAdapter.clear();
                listKey();
            }
        });

        builder.setNegativeButton("Cancel", null);
        // create and show the alert dialog
        AlertDialog dialog = builder.create();
        dialog.show();
    }

    private void generateKey() {
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        kst.importPrivateKey(privateKey);
        String fingerprint = getFingerprintSHA256Base64(privateKey);

        // setup the alert builder
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Key was Generated");
        builder.setMessage("key fingerprint\n" + fingerprint);
        builder.setPositiveButton("OK", null);
        AlertDialog dialog = builder.create();
        dialog.show();

        arrayAdapter.clear();
        listKey();
    }

    private void listKey() {
        List<String> fingerprints = kst.getFingerPrints();
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("key count %d\n", fingerprints.size()));
        int n = 1;
        for (String fingerprint: fingerprints) {
            sb.append(String.format("%d: ", n++));
            sb.append(fingerprint + "\n");
        }
        arrayAdapter.add(sb.toString());
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mPref = PreferenceManager.getDefaultSharedPreferences(this);
        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        mKeyguardManager = (KeyguardManager)getSystemService(Context.KEYGUARD_SERVICE);

        mPagent = new Pagent(this, kst);

        if(mPref.getBoolean("firstStart", true)) {
            // 初めての起動
            SharedPreferences.Editor editor = mPref.edit();
            editor.putBoolean("firstStart", false);
            
            if (mKeyguardManager.isKeyguardSecure()) {
                editor.putBoolean("enable_sign_when_device_locked_by_keyguard", false);
            }
            editor.commit();
        }
        mPagent.signEnable(mPref.getBoolean("enable_sign_when_device_locked_by_keyguard", false));

        mComStateText = (TextView)findViewById(R.id.textView2);
        kst.setContext(this);

        listItems = new ArrayList<>();
        arrayAdapter = new ArrayAdapter<String>(this, R.layout.rowdata, listItems);
        ListView listView  = (ListView)findViewById(R.id.listview);
        listView.setAdapter(arrayAdapter);

        // importボタン
        findViewById(R.id.button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                importPrivateKey();
            }
        });

        // list keysボタン
        findViewById(R.id.button4).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                arrayAdapter.clear();
                listKey();
            }
        });

        // test (generate)
        findViewById(R.id.button6).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                generateKey();
            }
        });
        
        // remove
        findViewById(R.id.button7).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                removeKey();
            }
        });

        // BT switch
        CompoundButton sw = (CompoundButton)findViewById(R.id.bt_switch);
        if (mBluetoothAdapter == null) {
            sw.setChecked(false);
            sw.setEnabled(false);
        } else {
            sw.setChecked(mBluetoothAdapter.isEnabled());
            sw.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    if (isChecked) {
                        Intent intent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
                        startActivityForResult(intent, REQUEST_ENABLE_BT);
                    } else {
                        mBluetoothAdapter.disable();
                        btEnable(false);
                    }
                }
            });
        }
            
        // connect
        Button button = (Button)findViewById(R.id.connect_button);
        if (mBluetoothAdapter == null) {
            button.setEnabled(false);
        } else {
            button.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (!mBluetoothAdapter.isEnabled()) {
                        btEnable(false);
                        message("bt is disable");
                        return;
                    }

                    if (mChatService == null) {
                        mChatService = new BluetoothChatService(MainActivity.this, mHandler);
                    }

                    if (mChatService.getState() == BluetoothChatService.STATE_NONE)
                    {
                        // Start the Bluetooth chat services
                        mChatService.start();
                    }

                    // connect
                    mComStateText.setText("connecting..");
                    Intent serverIntent = new Intent(MainActivity.this, DeviceListActivity.class);
                    startActivityForResult(serverIntent, REQUEST_CONNECT_DEVICE_SECURE);
                }
            });
        }

        // clear
        findViewById(R.id.button5).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                arrayAdapter.clear();
            }
        });

        // 空きボタン
        findViewById(R.id.button8).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
            }
        });

        // bluetoothが使えない端末
        if (mBluetoothAdapter == null) {
            message("BT is not available");
            btEnable(false);
        }
    }

    @Override
    public void onStart() {
        super.onStart();
        if (mBluetoothAdapter == null) {
            
        } else if (!mBluetoothAdapter.isEnabled()) {
            if (mPref.getBoolean("enable_bluetooth_when_startup", false)) {
                Intent intent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
                startActivityForResult(intent, REQUEST_ENABLE_BT);
            } else {
            // Otherwise, setup the chat session
            }
        } else if (mChatService == null) {
            mChatService = new BluetoothChatService(this, mHandler);
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (mChatService != null) {
            mChatService.stop();
        }
    }

    @Override
    public void onResume() {
        super.onResume();

        // Performing this check in onResume() covers the case in which BT was
        // not enabled during onStart(), so we were paused to enable it...
        // onResume() will be called when ACTION_REQUEST_ENABLE activity returns.
        if (mChatService != null) {
            // Only if the state is STATE_NONE, do we know that we haven't started already
            if (mChatService.getState() == BluetoothChatService.STATE_NONE) {
                // Start the Bluetooth chat services
                mChatService.start();
            }
        }
    }

    private boolean checkReadStragePermission() {
        // Android 6, API 23
        if (Build.VERSION.SDK_INT >= 23) {
            if (checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
        }
        return true;
    }
    
    // 許可を求める
    @TargetApi(23)
    private void requestReadStragePermission() {
        if (shouldShowRequestPermissionRationale(Manifest.permission.READ_EXTERNAL_STORAGE)) {
            requestPermissions(
                    new String[]{Manifest.permission.READ_EXTERNAL_STORAGE},
                                              REQUEST_READ_STORAGE_PERMISSION);
        } else {
            // キャンセル扱いにする
        }
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (requestCode) {
        case REQUEST_CONNECT_DEVICE_SECURE:
            // When DeviceListActivity returns with a device to connect
            if (resultCode == RESULT_OK) {
                connectDevice(data, true);
            }
            break;
        case REQUEST_CONNECT_DEVICE_INSECURE:
            // When DeviceListActivity returns with a device to connect
            if (resultCode == RESULT_OK) {
                connectDevice(data, false);
            }
            break;
        case REQUEST_ENABLE_BT:
            // When the request to enable Bluetooth returns
            if (resultCode == RESULT_OK) {
                mChatService = new BluetoothChatService(this, mHandler);
            } else {
                ((CompoundButton)findViewById(R.id.bt_switch)).setChecked(false);

                // User did not enable Bluetooth or an error occurred
                if (mChatService != null) {
                    mChatService.stop();
                    mChatService = null;
                }
                arrayAdapter.add("bt disabled");
            }
            break;
        case REQUEST_SETTING:
            mPagent.signEnable(mPref.getBoolean("enable_sign_when_device_locked_by_keyguard", false));
            break;
        }
    }

    // 結果の受け取り
    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        if (requestCode == REQUEST_READ_STORAGE_PERMISSION) {
            if (grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                importPrivateKeyI();
            }
        }
    }

    // メニュー作成
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
    	getMenuInflater().inflate(R.menu.menu, menu);
    	return true;
    }

    // メニューアイテム選択イベント
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
        case R.id.GENERATE_KEY:
            generateKey();
            break;
        case R.id.IMPORT_KEY:
            importPrivateKey();
            break;
        case R.id.LIST_KEY:
            listKey();
            break;
        case R.id.REMOVE_KEY:
            removeKey();
            break;
        case R.id.SETTING:
            Intent intent = new Intent(this, SettingsActivity.class);
            startActivityForResult(intent, REQUEST_SETTING);
            break;
        }
        return true;
    }

    /**
     * Establish connection with other device
     *
     * @param data   An {@link Intent} with {@link DeviceListActivity#EXTRA_DEVICE_ADDRESS} extra.
     * @param secure Socket Security type - Secure (true) , Insecure (false)
     */
    private void connectDevice(Intent data, boolean secure) {
        // Get the device MAC address
        String address = data.getExtras()
                .getString(DeviceListActivity.EXTRA_DEVICE_ADDRESS);
        // Get the BluetoothDevice object
        BluetoothDevice device = mBluetoothAdapter.getRemoteDevice(address);
        // Attempt to connect to the device
        mChatService.connect(device, secure);
    }
}

