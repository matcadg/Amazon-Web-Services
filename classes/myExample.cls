/*
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, 
SignedHeaders=host;range;x-amz-date,
Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
*/
String filePath = '/folder1/test.txt';
Blob payload = Blob.valueOf('myFileBody');
Integer contentlength = payload.size();
String bucketName = 'mybucket';

HttpRequest req = new HttpRequest();
String host = bucketName+'.s3.amazonaws.com';
String endpoint = host+filePath;
String method = 'PUT';
req.setEndpoint(endpoint);
req.setMethod(method);
req.setBodyAsBlob(payload);
//Authenticating a Request in the Authorization Header
String algorithm = 'AWS4-HMAC-SHA256';

String yourAccessKeyId = 'myKey';
String date = System.now().formatGmt('yyyyMMdd');
String xAmzDate = date + 'T' + System.now().formatGmt('HHmmss') + 'Z';
String awsRegion = 'awsRegion';
String credential = yourAccessKeyId+'/'+
					date+'/'+
					awsRegion+'/s3/aws4_request';

String signedHeaders = 'content-length;host;x-amz-date';

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
String canonicalMethod = method;
String canonicalUri = EncodingUtil.urlEncode(filePath, 'UTF-8');
String canonicalQuery = EncodingUtil.urlEncode('', 'UTF-8');
String canonicalHeaders = 	'content-length:'+String.valueOf(contentlength)+'\n'+
							'host:'+host+'\n'+
							'x-amz-date:'+xAmzDate;
String canonicalSignedHeaders = signedHeaders;
String canonicalHashedPayload = EncodingUtil.convertToHex(Crypto.generateDigest('SHA-256', payload));

String canonicalRequest = 	canonicalMethod+'\n'+
							canonicalUri+'\n'+
							canonicalQuery+'\n'+
							canonicalHeaders+'\n'+
							canonicalSignedHeaders+'\n'+
							canonicalHashedPayload;
//Task 2: Create a String to Sign
/*
"AWS4-HMAC-SHA256" + \n" +
timeStampISO8601Format + "\n" +
<Scope> + "\n" +
Hex(SHA256Hash(<CanonicalRequest>))
*/
String xscope = date+'/'+awsRegion+'/s3/aws4_request'
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
Blob dateKey = Crypto.generateMac('HmacSHA256', blob.valueof(date),blob.valueof('AWS4'+secretKey));
Blob dateRegionKey = Crypto.generateMac('HmacSHA256', blob.valueof(awsRegion),dateKey);
Blob dateRegionServiceKey = Crypto.generateMac('HmacSHA256', blob.valueof('s3'),dateRegionKey);
Blob signingKey = Crypto.generateMac('HmacSHA256', blob.valueof('aws4_request'),dateRegionServiceKey);

Blob sig = Crypto.generateMac('HmacSHA256', blob.valueof(stringToSign),signingKey);
signature = EncodingUtil.base64Encode(sig);
   
//AUTHORIZATION HEADER
String authorization =  algorithm+
						' Credential='+credential+
						',SignedHeaders='+signedHeaders+
						',Signature='+signature;

//Blob headerValue = Blob.valueOf(algorithm);
//String authorization = algorithm + EncodingUtil.base64Encode(headerValue);
req.setHeader('Authorization', authorization);

//SEND
Http http = new Http();
HttpResponse res = http.send(req);
