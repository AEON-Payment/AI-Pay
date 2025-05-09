# Environmental Information
Sandbox Environment: https://ai-api-sbx.aeon.xyz  
Production Environment: https://ai-api.aeon.xyz

# Signature Description
## Signature Generation and Verification

### 1. Obtain `secrete`

Please check the **Merchant Dashboard** information in the email we sent you (if you haven't received it, contact our business manager). Log in to the **Merchant Dashboard** to obtain the `secrete`.  
The `secrete` is mainly used for **hashing and signing** the input parameters of the API request. Merchants should **keep it secure** and ensure **the key is not leaked**.

***

### **2. Generate the Signature String**

#### **Signature Rules**

1. Combine all **parameters that need to be verified** into an array.
2. **Sort the parameters by key name in ascending ASCII order**. Only the **parameter keys** are sorted, not the values.
3. All required fields must be **filled in** (excluding `sign`).
4. The format for concatenation: **`parameterName=parameterValue`**. Multiple parameters are separated by `&`, and **append `key (secrete)`** at the end.

***

#### **Signature Example**

**Example Parameters:**

```json
{
    "appId": "TEST000001",
    "sign": "TEST000001",
    "merchantOrderNo": "11126"
}
```

**Concatenated Signature String:**

```
appId=TEST000001&merchantOrderNo=11126&key=9999
```

**Use SHA-512 to hash and sign, resulting in the final signature:**

```
95960053CC577FCAFC272410D5F70094DD0986F6C3266DB7D00D0B37A7CB12F6607125143987143EE168DA052C0A1FD436A0E14DBA57584CC977F82823318BDC
```

***

### **3. Java Signature Utility Class**

#### **SHA-512 Signature Tool**

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

public class SHA512Utils {
    public static final String ENCODE = "UTF-8";

    /**
     * Perform SHA-512 signature
     *
     * @param signParams  Signature parameters
     * @param key         Secret key
     * @return            Generated signature
     */
    public static String SHAEncrypt(TreeMap<String, String> signParams, String key) {
        signParams.remove("sign");
        StringBuilder sb = new StringBuilder();
        Set es = signParams.entrySet();
        Iterator it = es.iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            String k = (String) entry.getKey();
            String v = (String) entry.getValue();
            if (v != null && !v.isEmpty() && !"sign".equals(k) && !"key".equals(k)) {
                sb.append(k).append("=").append(v).append("&");
            }
        }
        sb.append("key=").append(key);
        return encrypt(sb.toString(), ENCODE).toUpperCase();
    }

    /**
     * Perform SHA-512 encryption
     */
    public static String encrypt(String aValue, String encoding) {
        aValue = aValue.trim();
        byte[] value;
        try {
            value = aValue.getBytes(encoding);
        } catch (UnsupportedEncodingException e) {
            value = aValue.getBytes();
        }
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        return toHex(md.digest(value));
    }

    /**
     * Convert byte array to hexadecimal string
     */
    public static String toHex(byte[] input) {
        if (input == null) return null;
        StringBuilder output = new StringBuilder(input.length * 2);
        for (byte b : input) {
            int current = b & 0xff;
            if (current < 16) output.append("0");
            output.append(Integer.toString(current, 16));
        }
        return output.toString();
    }

    /**
     * Verify SHA-512 signature
     *
     * @param signParams  Signature parameters
     * @param key         Secret key
     * @return            Whether the signature is valid
     */
    public static boolean verifySHA(TreeMap<String, String> signParams, String key) {
        String verifySign = signParams.get("sign");
        String sign = SHAEncrypt(signParams, key);
        return sign.equalsIgnoreCase(verifySign);
    }
}
```

***

### **4. Java Signature Generation Example**

```java
import java.util.Map;
import com.alibaba.fastjson.JSONObject;

public class SignTest {
    public static void main(String[] args) {
        String jsonData = "{\n" +
                            " \"appId\": \"TEST000001\",\n" +
                            " \"sign\": \"TEST000001\",\n" +
                            " \"merchantOrderNo\": \"11126\"\n" +
                            "}\n";
        
        // Parse the JSON data and convert it to a TreeMap
        TreeMap<String, String> resultMap = JSONObject.parseObject(jsonData, TreeMap.class);
        
        // Generate the signature
        String result = SHA512Utils.SHAEncrypt(resultMap, "9999");
        System.out.println("Generated signature: " + result);

        // Add the signature and verify
        resultMap.put("sign", "95960053CC577FCAFC272410D5F70094DD0986F6C3266DB7D00D0B37A7CB12F6607125143987143EE168DA052C0A1FD436A0E14DBA57584CC977F82823318BDC");
        System.out.println("Signature verification result: " + SHA512Utils.verifySHA(resultMap, "9999"));
    }
}
```
