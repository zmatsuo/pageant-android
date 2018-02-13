# このプログラムについて

BT pageant+ for android

Windows用のpageant+と通信するssh-ageant。

# できること

- sshの秘密鍵をandroidのkeystoreに保存できる
- 署名をandroid上で行える
- pageant+を使うことができるプログラム全てで使用できる

# 大雑把な使い方

## インストール

- apkを作成してandroidにインストール

## Windowsと通信

- BTペアリングを行う
- BT ageant+を起動しておく

## 鍵のインポート

- 鍵はバックアップするなどして失われても良い状態にしておく
- DER(PKCS#8)形式秘密鍵を準備  
    `openssl pkcs8 -topk8 -in private_key.pem -inform pem -out private_key.der -outform der -nocrypt`
- 秘密鍵をandroidに転送
- importボタンを押して秘密鍵を指定
- derファイルは不要なので削除する
 
## 鍵の新しい鍵の作成

- Generateボタンを押して秘密鍵を作成
- pageant+で公開鍵を取り出す

# 利点

- 秘密鍵を ~/.sshに置きっぱなしにせずに持ち運べる
- 秘密鍵はandroidのkeystoreに保存
- 無線で使用できる
- etc...

# 欠点

- 動作が遅い
- etc...

# 制限

- サービスとして動作していないので、いつの間にか通信できなくなったりする。
  再度起動すれば使用可能
- 1台のPCとのみペアリングする  
  2台以上のPCを同時に使っているとき同時に使用できない


# license

- putty+ android MIT license

- spongycastle  
  https://rtyley.github.io/spongycastle/
- filechooser  
  https://github.com/hedzr/android-file-chooser
- BluetoothChatService.java,  
  Constants.jave,  
  DeviceListActivity.java,  
  https://developer.android.com/samples/index.html
  Apache License
- PrivateKeyReader.java  
  Apache License
