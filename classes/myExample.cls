//CHECK Date header and standard

String filePath = '/test2.txt';
Blob payload = Blob.valueOf('myFileBodyupdated');
Integer contentlength = payload.size();
String bucketName = 'matcadev';

HttpRequest req = new HttpRequest();
String host = bucketName+'.s3.amazonaws.com';
String endpoint = 'https://'+host+filePath;//s3.eu-central-1.amazonaws.com
String method = 'PUT';
req.setEndpoint(endpoint);
req.setMethod(method);
req.setBodyAsBlob(payload);
//Authenticating a Request in the Authorization Header
String algorithm = 'AWS4-HMAC-SHA256';

String yourAccessKeyId = 'KEY';
String longTime = System.now().formatGMT('EEE, dd MMM yyyy HH:mm:ss')+' GMT';
String xdate = System.now().formatGmt('yyyyMMdd');
String xAmzDate = xdate + 'T' + System.now().formatGmt('HHmmss') + 'Z';
String awsRegion = 'eu-central-1';
String credential = yourAccessKeyId+'/'+
					xdate+'/'+
					awsRegion+'/s3/aws4_request';

String signedHeaders = 'date;host;x-amz-content-sha256;x-amz-date';

//Calculating a Signature
String signature;
//Task 1: Create a Canonical Request
/*
<HTTPMethod>\n
<CanonicalURI>\n
<CanonicalQueryString>\n
<CanonicalHeaders>\n
<SignedHeaders>\n
<HashedPayload>
*/
String canonicalHashedPayload = EncodingUtil.convertToHex(Crypto.generateDigest('SHA-256', payload));

String canonicalMethod = method;
//don't encode forward slash in file path
String canonicalUri = filePath;//EncodingUtil.urlEncode(filePath, 'UTF-8');
String canonicalQuery = EncodingUtil.urlEncode('', 'UTF-8');
String canonicalHeaders = 	//'content-length:'+contentlength+'\n'+
							'date:'+longTime+'\n'+
							'host:'+host+'\n'+
							'x-amz-content-sha256:'+canonicalHashedPayload+'\n'+
							'x-amz-date:'+xAmzDate+'\n';
String canonicalSignedHeaders = signedHeaders;


String canonicalRequest = 	canonicalMethod+'\n'+
							canonicalUri+'\n'+
							canonicalQuery+'\n'+
							canonicalHeaders+'\n'+
							canonicalSignedHeaders+'\n'+
							canonicalHashedPayload;
System.debug('canonicalRequest:\n'+canonicalRequest);
//Task 2: Create a String to Sign
/*
"AWS4-HMAC-SHA256" + \n" +
timeStampISO8601Format + "\n" +
<Scope> + "\n" +
Hex(SHA256Hash(<CanonicalRequest>))
*/
String xscope = xdate+'/'+awsRegion+'/s3/aws4_request';
String stringToSign = 	algorithm + '\n' +
						xAmzDate  + '\n' +
						xscope	  + '\n' +
						EncodingUtil.convertToHex(Crypto.generateDigest('SHA-256', Blob.valueOf(canonicalRequest)));

//Task 3: Calculate Signature
/*
DateKey              = HMAC-SHA256("AWS4"+"<SecretAccessKey>", "<yyyymmdd>")
DateRegionKey        = HMAC-SHA256(<DateKey>, "<aws-region>")
DateRegionServiceKey = HMAC-SHA256(<DateRegionKey>, "<aws-service>")
SigningKey           = HMAC-SHA256(<DateRegionServiceKey>, "aws4_request")
*/
String secretKey = 'SECRET';
Blob dateKey = Crypto.generateMac('HmacSHA256', blob.valueof(xdate),blob.valueof('AWS4'+secretKey));
Blob dateRegionKey = Crypto.generateMac('HmacSHA256', blob.valueof(awsRegion),dateKey);
Blob dateRegionServiceKey = Crypto.generateMac('HmacSHA256', blob.valueof('s3'),dateRegionKey);
Blob signingKey = Crypto.generateMac('HmacSHA256', blob.valueof('aws4_request'),dateRegionServiceKey);

Blob sig = Crypto.generateMac('HmacSHA256', blob.valueof(stringToSign),signingKey);
//signature = EncodingUtil.base64Encode(sig);
signature = EncodingUtil.convertToHex(sig);//correct one
   System.debug('base64:'+EncodingUtil.base64Encode(sig));
   System.debug('hex:'+EncodingUtil.convertToHex(sig));

//AUTHORIZATION HEADER
/*
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, 
SignedHeaders=host;range;x-amz-date,
Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
*/
String authorization =  algorithm+
						' Credential='+credential+
						',SignedHeaders='+signedHeaders+
						',Signature='+signature;

//Blob headerValue = Blob.valueOf(algorithm);
//String authorization = algorithm + EncodingUtil.base64Encode(headerValue);
req.setHeader('Content-Length', String.valueOf(contentlength));
req.setHeader('Date',longTime);
req.setHeader('Host', host);
req.setHeader('x-amz-content-sha256', canonicalHashedPayload);
req.setHeader('x-amz-date', xAmzDate);

req.setHeader('Authorization', authorization);

//SEND
Http http = new Http();
System.debug('request:'+req);
HttpResponse res = http.send(req);
System.debug(res + res.getBody());
