# iOS DeviceCheck and App Attest 
Reduce fraudulent use of your services by managing device state and asserting app integrity. <br>
<img src = "https://github.com/Nimol11/video/blob/main/folder/Screenshot%202024-07-18%20at%208.29.40%20in%20the%20morning.png" width="500px"/>  <br>

#:eyes: Instructions 

##### :arrow_right: [DeviceCheck](#device-check)
[1. Check for availability](#check-for-availability) <br> 
[2. Generate Device Token](#generate-device-token) <br>

##### :arrow_right: [app-attest](#app-attest)
[1. Check for availability](#check-for-availability) <br>
[2. Create a key pair](#create-a-key-pair) <br> 
[3. Certify the key pairs as valid](#certify-the-key-pairs-as-valid) <br>
[4. Assert your app’s validity as necessary](#assert-your-app-validity-as-necessary) <br>


# <a name="device-check">Device check </a>

The DeviceCheck services consist of both a framework interface that you access from your app and an Apple server interface that you access from your own server.
    
Using the DCDevice class in your app, you can get a token that you use on your server to set and query two binary digits of data per device, while maintaining user privacy. For example, you might use this data to identify devices that have already taken advantage of a promotional offer that you provide, or to flag a device that you’ve determined to be fraudulent. The server-to-server APIs also let you verify that the token you receive comes from your app on an Apple device.
    


:eye: Note that DeviceCheck will only work on physical device, it will not work on simulator. You can user .isSupported to check if the current device support DeviceCheck API.
<br> You will also <b> need to have a valid Apple Developer Account </b> and sign your project .

### <a name="check-for-availability"> Check for availability </a>

```swift
import DeviceCheck

let device = DCDevice.current
guard device.isSupported else {
    print("Unsupported device: Please use in a real device instead of simulator")
return
}
```
This code is check if your device is support DeviceCheck API.

### <a name="generate-device-token">Generate Device Token </a>

```swift 
import DeviceCheck

let device = DCDevice.current
device.generateToken(completionHandler: { data, error in
      let deviceToken = data.base64EncodedString() 
      
      // sent this device token to sever validation 
}
```
This Code we use a DeviceCheck device by calling <b> DCDevice.current </b>, then we generate a token using <b> .generateToken </b>, and then we need to encode the token raw data to base64 encoding. Finally we sent it to backend Server.
<br> <b>You will also read more detail: [Apple DeviceCheck](https://developer.apple.com/documentation/devicecheck) </b>


# <a name="app-attest"> App Attest </a>

Ensure that requests your server receives come from legitimate instances of your app.                           
<br> You can’t rely on your app’s logic to perform security checks on itself because a compromised app can falsify the results. Instead, you use the sharedService instance of the DCAppAttestService class in your app to create a to certify that the key belongs to a valid instance of your app. Then you use the service to cryptographically sign server requests using the certified key. Your app uses these measures to assert its legitimacy with any server requests for sensitive or premium content.


:book: Need to add App Attest in capability 

### <a name="check-for-availability> Check for availability </a>

```swift 
import DeviceCheck 
    
let appAttestService = DCAppAttestService()
guard appAttestService.isSupported else {
    print("Unsupported device")
    return
}

// continue your next step 
```
 This code will check  your device is support App Attest service .

### <a name="create-a-key-pair"> Create a key pair </a>

:eye: For each user account on each device running your app, generate a unique, hardware-based, cryptographic key pair.

```swift 
appAttestService.generateKey { [weak self] keyId , error in
      // Cache keyId for subsequent operations.
}
```

On success, the method’s completion handler returns a key identifier that you use later to access the key.

### <a name="certify-the-key-pairs-as-valid"> Certify the key pairs as valid </a>

:book: Before using a key pair, ask Apple to attest to its origin on Apple hardware running an uncompromised version of your app. Because you can’t trust your app’s logic to verify the attestation result, you send the result to your server. To reduce the risk of replay attacks during this procedure, attestation embeds the hash of a unique, one-time challenge from your server. 

```swift 

import CryptoKit

let challenge = <# challenge retrieve from server #>
let hash = Data(SHA256.hash(data: Data(challenge.utf8)))

```
Using the hash, along with the key pair you create in the previous section to initiate attestation.

```swift 

appAttestService.attestKey(keyId, clientDataHash: hash) {  attestation, error in
    let attestationString = attestation?.base64EncodedString()
    // Send the attestationString to your server for verification. 
}

```
### <a name="assert-your-app-validity-as-necessary"> Assert your app’s validity as necessary </a>
:book: After successfully verifying a key’s attestation, your server can require the app to assert its legitimacy for any or all future server requests.

```swift 
let request = [ "action": "getGameLevel",
                "levelId": "1234",
                "challenge": challenge ]
guard let clientData = try? JSONEncoder().encode(request) else { return }
let client = String(data: clientData, encoding: .utf8)

appAttestService.generateAssertion(keyId, clientDataHash: hash) { assertionObject , error in
    let attestationString = assertionObject?.base64EncodedString()
    
    // sent attestationString, client and challenge to server  
}
                  
``` 
