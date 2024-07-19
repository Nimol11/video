# iOS DeviceCheck and App Attest
Reduce fraudulent use of your services by managing device state and asserting app integrity. <br>

<img src = "https://github.com/Nimol11/video/blob/main/folder/Screenshot%202024-07-18%20at%208.29.40%20in%20the%20morning.png?raw=true" width="500px"/>


# :book: Project Preparing 

1. Java version 22
2. Spring boot  3.3.3
3. Project Maven 
4. Project dependencies

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk15on</artifactId>
    <version>1.68</version>
</dependency>

<dependency>
    <groupId>ch.veehait.devicecheck</groupId>
    <artifactId>devicecheck-appattest</artifactId>
    <version>0.9.6</version>
</dependency>

<dependency>
     <groupId>io.jsonwebtoken</groupId>
     <artifactId>jjwt-api</artifactId>
     <version>0.11.2</version> 
</dependency>
```
# :eyes: Instructions

#### :arrow_right: DeviceCheck

[1. How to get KeyID](#how-to-get-keyid) <br>
[2.Generate JWT Token Key In server](#generate-jwt-token-key-in-server) <br>
[3. Query two bits](#query-two-bits) <br>
[4. Update two bits](#update-two-bits)

 ##### :arrow_right: App Attest 
[App Attest](#app-attest) <br> <br>
[1. App Configuration](#app-configuration) <br>
[2. App Service Flow](#app-service-flow) <br>

 [some library for app attest](#some-library-for-app-attest)




The DeviceCheck services consist of both a framework interface that you access from your app and an Apple server interface that you access from your own server.

Using the DCDevice class in your app, you can get a token that you use on your server to set and query two binary digits of data per device, while maintaining user privacy. For example, you might use this data to identify devices that have already taken advantage of a promotional offer that you provide, or to flag a device that you’ve determined to be fraudulent. The server-to-server APIs also let you verify that the token you receive comes from your app on an Apple device.


## How to get keyId
Before we proceeding to the server code, Firstly wee need to generate a DeviceCheck Key on Apple Developer Console.
<br> <b> [Read This for how to get private key for using in apple service api](https://developer.apple.com/help/account/manage-keys/create-a-private-key)</b>

<img src = "https://github.com/Nimol11/video/blob/main/folder/Screenshot%202024-07-18%20at%209.24.19%20in%20the%20morning.png?raw=true" width = "500px" />

Click continue. download the key file, and also copy the key ID, we will need this later on.

<img src = "https://github.com/Nimol11/video/blob/main/folder/Screenshot%202024-07-18%20at%209.34.24%20in%20the%20morning.png?raw=true" width = "500px" />

:eye: NOTE if you download the file with <b> .p8 </b> extension you need to store in your secure folder because when you download this file apple will remove from app developer account, so you will not be able to download again.

# Generate JWT Token Key In server

In this step we need to generate JWT Token to Authorization for communication with Apple DeviceCheck API to verify that the server it own by you.

<b> For gerate JWT Toke we need:  </b>

<br> <b> Apple Key ID </b>
<br> <b> Team ID </b>
<br> file <b> .p8 </b> in this file have private key we also need this private key to generate token 

 <b> In this process apple user ES256 algorithm to generate JWT Token </b>

:eye: Sample code below is using java spring boot to generate JWT

In application.properties file:

 ```java 
 
devicecheck.key-string=YOUR_PRIVATE_KEY
devicecheck.key-id=YOUR_KEY_ID
devicecheck.team-id=YOUR_TEAM_ID

 ```

 ```java 
 @Service
 public class JwtService {

    @Value("${devicecheck.key-string}")
    private String privateKeyString;

    @Value("${devicecheck.key-id}")
    private String keyId;

    @Value("${devicecheck.team-id}")
    private String teamId;

    public String generateJwtToken() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String keyString = privateKeyString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);

        long now = System.currentTimeMillis();

        return Jwts.builder()
                .setHeaderParam("kid", keyId)
                .setIssuer(teamId)
                .setIssuedAt(new Date(now))
                .signWith(privateKey, SignatureAlgorithm.ES256)
                .compact();
    }
}

 ``` 
### Query Two bits

:key: To get two bits state of a device, we will make a HTTP request to apple api:
<br> [https://api.devicecheck.apple.com/v1/query_two_bits](https://api.devicecheck.apple.com/v1/query_two_bits) (this is for the production server for app are in App store or Testflight)
<br> [https://api.development.devicecheck.apple.com/v1/query_two_bits](https://api.development.devicecheck.apple.com/v1/query_two_bits) (for this use with app in development process)

<img src = "https://github.com/Nimol11/video/blob/main/folder/Screenshot%202024-07-18%20at%2010.13.34%20in%20the%20morning.png?raw=true" width="500px" />

We will make a POST request to apple server with JSON body device_token, timestamp and transaction_id.

<br> <b> device_token </b>is the Base64 string encoding token generate from app 

<br> <b> timestamp </b> is the current time in Unix, Timestamp when you sent request to apple server, in <b> milliseconds </b>

<br> <b> transaction_id </b> is a unix string, this can be any string you want, as long as each HTTP request you make to Apple server using a different transaction_id.

:eye: Sample Code below:

```java
public class Token {
    private  String deviceToken;
    private  boolean bit0;
    private  boolean bit1;

   // setter and getter 
}

```

```java 
@PostMapping("/query_two_bits")
public ResponseEntity<String> queryTwoBits(@RequestBody Token token) throws Exception {
    String jwtToken = jwtService.generateJwtToken();
    HttpHeaders headers = new HttpHeaders();
    headers.set("Authorization", "Bearer "+ jwtToken );
    Map<String, Object> payload = new HashMap<>();
    payload.put("device_token", token.getDeviceToken());
    payload.put("timestamp", System.currentTimeMillis());
    payload.put("transaction_id", UUID.randomUUID().toString());
    HttpEntity<Map<String, Object>> request = new HttpEntity<>(payload, headers);
    String queryUrl = "https://api.development.devicecheck.apple.com/v1/query_two_bits"; 
    return restTemplate.exchange(queryUrl, HttpMethod.POST, request, String.class);
}

```
:arrow_right: if the bits state of device haven't set before, Apple will response HTTP status <b>200 </b>  and a text <b> Device not found</b>, this text text will change.
<br> :arrow_right: if the bits state of the device has been set before, Apple server will response HTTP status <b> 200 </b> and JSON Body

<img src = "https://github.com/Nimol11/video/blob/main/folder/Screenshot%202024-07-18%20at%2010.29.52%20in%20the%20morning.png?raw=true" width = "500px" />


### Update Two bits


:key: To update two bits state of a device, we will make a HTTP request to apple api:
[https://api.devicecheck.apple.com/v1/update_two_bits](https://api.devicecheck.apple.com/v1/update_two_bits) (this is for the production server for app are in App store or Testflight)
[https://api.development.devicecheck.apple.com/v1/update_two_bits](https://api.development.devicecheck.apple.com/v1/update_two_bits) (for this use with app in development process)
<img src = "https://github.com/Nimol11/video/blob/main/folder/Screenshot%202024-07-18%20at%2010.33.46%20in%20the%20morning.png?raw=true" width="500px" />

We will make a POST request to Apple server with JSON body device_token, timestamp, transaction_id, bit0 and bit1.

<br> <b> device_token </b>is the Base64 string encoding token generate from app 

<br> <b> timestamp </b> is the current time in Unix, Timestamp when you sent request to apple server, in <b> milliseconds </b>

<br> <b> transaction_id </b> is a unix string, this can be any string you want, as long as each HTTP request you make to Apple server using a different transaction_id.

<br> <b> bit0 </b> is a boolean, you can set this both true or false.

<br> <b> bit1 </b> is a boolean, you can set this both true or false.

:eye: Sample code below

```java 
@PostMapping("/update_two_bits")
public ResponseEntity<String> updateTwoBits(@RequestBody Token token) throws Exception {
    String jwtToken = jwtService.generateJwtToken();
    HttpHeaders headers = new HttpHeaders();
    headers.set("Authorization", STR."Bearer \{jwtToken}");
    Map<String, Object> payload = new HashMap<>();
    payload.put("device_token", token.getDeviceToken());
    payload.put("timestamp", System.currentTimeMillis());
    payload.put("transaction_id", UUID.randomUUID().toString());
    payload.put("bit0", token.isBit0());
    payload.put("bit1", token.isBit1());
    HttpEntity<Map<String, Object>> request = new HttpEntity<>(payload, headers);
    String updateUrl = "https://api.development.devicecheck.apple.com/v1/update_two_bits";
    return restTemplate.exchange(updateUrl, HttpMethod.POST, request, String.class);
}
    
```

:arrow_right: Apple server will response HTTP status 200 and empty body if the update is successful.


#  App Attest

Ensure that requests your server receives come from legitimate instances of your app.                           
<br> You can’t rely on your app’s logic to perform security checks on itself because a compromised app can falsify the results. Instead, you use the sharedService instance of the DCAppAttestService class in your app to create a to certify that the key belongs to a valid instance of your app. Then you use the service to cryptographically sign server requests using the certified key. Your app uses these measures to assert its legitimacy with any server requests for sensitive or premium content.



In this section we use library to implement

:key: Link: [https://github.com/veehaitch/devicecheck-appattest](https://github.com/veehaitch/devicecheck-appattest)

In server side we need <b> Team ID </b> and <b> bundle Identifier </b>

### App configuration

Sample Code below

```java 

@Configuration
public class AppAttestConfig {
    @Bean
    public AppleAppAttest appleAppAttest() {
        AppleAppAttest appleAppAttest = new AppleAppAttest(
                new App("team id", "bundle identifier"),
                AppleAppAttestEnvironment.DEVELOPMENT
        );
        return  appleAppAttest;
    }
    
    @Bean
    public AttestationValidator attestationValidator(AppleAppAttest appleAppAttest) {
        return  appleAppAttest.createAttestationValidator();
    }

    @Bean
    public AssertionValidator assertionValidator(AppleAppAttest appleAppAttest) {
        return appleAppAttest.createAssertionValidator(new AssertionChallengeValidator() {
            @Override
            public boolean validate(@NotNull Assertion assertion,  byte[] bytes, @NotNull ECPublicKey ecPublicKey, byte[] bytes1) {
                return true;
            }
        });
    }
}

```
### App service flow

Sample code below

```java 

@Service
public class AppAttestService {
    private  final AttestationValidator attestationValidator;
    private final AssertionValidator assertionValidator;

    @Autowired
    public  AppAttestService(AttestationValidator attestationValidator, AssertionValidator assertionValidator) {
        this.attestationValidator = attestationValidator;
        this.assertionValidator = assertionValidator;
    }
    public AppAttestResponse validateAttestation(AppAttestRequest request) {
        try {
            ValidatedAttestation result = attestationValidator.validate(
                    Base64.getDecoder().decode(request.getAttestationObject()),
                    request.getKeyIdBase64(),
                    request.getServerChallenge().getBytes()
            );
            ECPublicKey publicKey = (ECPublicKey) result.getCertificate().getPublicKey();
            X509Certificate certificate = result.getCertificate();
            return new AppAttestResponse(publicKey,result.getIOSVersion(), result.getReceipt().toString());
        }catch (Exception e) {
            return new AppAttestResponse();
        }
    }
    public boolean validateAssertion(AppAttestVerify verify, ECPublicKey publicKey) {
        AppAttestResponse response = new AppAttestResponse();

        try {
            Assertion result = assertionValidator.validate(
                    Base64.getDecoder().decode(verify.getAssertionObject()),
                    verify.getClientData().getBytes(),
                    publicKey,
                    0,
                    verify.getChallenge().getBytes()
            );
            return true;
        } catch (Exception e) { 
            return false ;
        }
    }
}

```

## Some library for App attest

Go: [https://github.com/bas-d/appattest](https://github.com/bas-d/appattest)
<br> swift: [https://github.com/iansampson/AppAttest](https://github.com/iansampson/AppAttest)
<br> Node: [https://github.com/srinivas1729/appattest-checker-node](https://github.com/srinivas1729/appattest-checker-node)
<br> java|kotlin: [https://github.com/veehaitch/devicecheck-appattest](https://github.com/veehaitch/devicecheck-appattest)
