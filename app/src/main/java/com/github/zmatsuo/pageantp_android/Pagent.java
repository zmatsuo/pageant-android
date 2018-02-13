
package com.github.zmatsuo.pageantp_android;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import static com.github.zmatsuo.pageantp_android.Sign.getPublicKey;
import static com.github.zmatsuo.pageantp_android.Sign.sign_data;

interface IPagent {
    void write(byte[] data);
    void message(String s);
}

class Pagent {

    IPagent mIf;
    KeyStoreTest mKeyStore;

    private boolean mSignEnabled;
    private static final int SSH_AGENT_FAILURE = 0x05;
    private static final int SSH2_AGENTC_REQUEST_IDENTITIES = 0x0b;
    private static final int SSH2_AGENT_IDENTITIES_ANSWER = 0xc;
    private static final int SSH2_AGENTC_SIGN_REQUEST = 0x0d;
    private static final int SSH2_AGENT_SIGN_RESPONSE = 0x0e;
    
    public Pagent(IPagent ifapi,
                  KeyStoreTest keyStore
        ) {
        mIf = ifapi;
        mKeyStore = keyStore;
    }

    private void message(String s) {
        mIf.message(s);
    }

    public String message_read(byte[] readBuf) {
        int len = readBuf.length;
        message(String.format("receive %d(0x%x)bytes", len, len));
        String s = null;
        // construct a string from the valid bytes in the buffer
        //String readMessage = new String(readBuf, 0, msg.arg1);
        //mConversationArrayAdapter.add(mConnectedDeviceName + ":  " + readMessage);
        //String s = "read " + mConnectedDeviceName + readMessage;
        //Log.d(TAG, s);
        //message(s);
        //String s = Binutil.dump(readBuf, len);
        //message(s);

        if (len < 5) {
            message("data too short");
            return s;
        }
                    
        int pos = 0;
        int whole_len = Binutil.getInt(readBuf, pos);
        int msg_no = readBuf[4];
        pos += 5;

        if (whole_len > 6*1024) {
            message("data too large");
            return s;
        }
        if (len < whole_len ) {
            message("data too short");
            return s;
        }

        message(String.format("msg_no %d(0x%x)", msg_no, msg_no));
        if (mSignEnabled) {
            switch(msg_no) {
            case SSH2_AGENTC_SIGN_REQUEST:
            {
                byte[] pubkey_bytes = getBin(readBuf, pos);
                pos += (4 + pubkey_bytes.length);
                byte[] data_bytes = getBin(readBuf, pos);
                pos += (4 + data_bytes.length);
                     
                message("pubkey");
                s = Binutil.dump(pubkey_bytes, 0);
                message(s);
                PublicKey publicKey = getPublicKey(pubkey_bytes);
                PrivateKey privateKey = mKeyStore.getPrivateKey(publicKey);
                if (privateKey == null){
                    message("unknown key?");
                    byte[] sendData = failure_msg();
                    mIf.write(sendData);
                } else {
                    message("data");
                    s = Binutil.dump(data_bytes, 0);
                    message(s);

                    byte[] signedData = sign_data(privateKey, data_bytes);

                    byte[] body1 = Binutil.getBinBin(signedData);
                    byte[] body1_header = Binutil.getBinStr("ssh-rsa");
                    byte[] body = Binutil.getBinBin(Binutil.cat(body1_header, body1));
                    byte[] send_data = makeSendData(SSH2_AGENT_SIGN_RESPONSE, body);
                    
                    s = Binutil.dump(send_data, 0);
                    message(s);

                    mIf.write(send_data);
                }
                break;
            }
            case SSH2_AGENTC_REQUEST_IDENTITIES:
            {
                List<PublicKey> keys = mKeyStore.getPublicKeys();
                List<byte[]> keysBin = new ArrayList<>();
                List<String> keysComment = new ArrayList<>();
                for (PublicKey publicKey: keys) {
                    byte[] publicKeyBin = Sign.getBin(publicKey);
                    keysBin.add(publicKeyBin);
                    keysComment.add("from bt agent");
                }
                int keysCount = keysBin.size();
                int keysLength = 0;
                for (int i = 0; i < keysCount; i ++) {
                    keysLength += 4 + keysBin.get(i).length;
                    keysLength += 4 + keysComment.get(i).length();
                }
	
                int length = 4 + 1 + 4 + keysLength;
                byte[] sendData = new byte[length];
                pos = 0;
                Binutil.putInt(sendData, pos, length-4);
                pos += 4;
                sendData[pos++] = SSH2_AGENT_IDENTITIES_ANSWER;
                Binutil.putInt(sendData, pos, keysCount);
                pos += 4;
                for (int i = 0; i < keysCount; i ++) {
                    pos = Binutil.putBin(sendData, pos, keysBin.get(i));
                    pos = Binutil.putBin(sendData, pos, keysComment.get(i));
                }

                s = Binutil.dump(sendData, 0);
                message(s);

                mIf.write(sendData);
                break;
            }
            default: {
                byte[] sendData = failure_msg();
                mIf.write(sendData);
                message(String.format("not implement"));
                break;
            }
            }
        } else {
            byte[] sendData = failure_msg();
            mIf.write(sendData);
            message(String.format("sign disabled"));
        }

        return s;
    }
    
    private byte[] getBin(final byte[] src, int pos) {
        int len = Binutil.getInt(src, pos);
        pos += 4;
        return Binutil.slice(src, pos, len);
    }
    

    private byte[] makeSendData(int msg, final byte[] body) {
        int len = body.length;
        byte[] send_data = new byte[4 + 1 + len];
        Binutil.putInt(send_data, 0, 1 + len);
        send_data[4] = (byte)msg;
        if (len > 0) {
            System.arraycopy(body, 0, send_data, 5, len);
        }
        return send_data;
    }

    private byte[] failure_msg()
    {
        final byte[] body = new byte[0];
        return makeSendData(SSH_AGENT_FAILURE, body);
    }

    public void signEnable(boolean enable) {
        mSignEnabled = enable;
    }
}
